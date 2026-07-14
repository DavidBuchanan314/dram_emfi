// SPDX-License-Identifier: GPL-2.0
/*
 * dropwrite: deterministically simulate a DRAM "dropped write" that lands on a
 * leaf PTE being zapped during an mmap(MAP_FIXED) over-map.
 *
 * Mechanism (see brainstorm): a MAP_FIXED remap tears the old mapping down
 * (munmap half) and then faults the new pages in (MAP_POPULATE half). The
 * munmap half issues two logically-distinct effects on the target leaf PTE
 * slot:
 *   1. the *store* that clears the PTE to 0, and
 *   2. the rmap/refcount teardown that frees the old page.
 * A physically dropped write to (1) leaves the PTE present while (2) still
 * frees the page -> stale PTE to a freed page == UAF.
 *
 * We can't cheaply skip the store deep inside the inlined zap, so instead we
 * bracket the teardown with a kretprobe on vms_clear_ptes (the MAP_FIXED
 * over-map path) and, on return, re-stamp the saved old PTE value back into
 * the slot. The kernel has already done the free half by then, so the end
 * state is byte-identical to a dropped zap store, but deterministic.
 *
 * The <2MB remap trick in the exploit keeps the leaf page-table page alive
 * across the teardown, so the ptep we saved on entry is still valid on return.
 *
 * Interface (debugfs, under /sys/kernel/debug/dropwrite):
 *   arm         (w) write a hex/dec vaddr to arm a one-shot drop for the
 *                   writing task's mm. 0 disarms.
 *   last_vaddr  (r) vaddr of the most recent preserved PTE
 *   last_pfn    (r) old PFN preserved at that vaddr
 *   hits        (r) number of drops performed since load
 */
#define pr_fmt(fmt) "dropwrite: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/debugfs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/pgtable.h>
#include <linux/uaccess.h>
#include <asm/tlbflush.h>

static struct dentry *ddir;

static bool debug;
module_param(debug, bool, 0644);
MODULE_PARM_DESC(debug, "verbose per-probe logging");
#define dw_dbg(fmt, ...) do { if (debug) pr_info(fmt, ##__VA_ARGS__); } while (0)

/* one-shot arm state; single target at a time is plenty for iterating */
static struct mm_struct *target_mm;   /* captured at arm time, not refcounted */
static unsigned long     armed_vaddr; /* 0 == disarmed */

static u64 last_vaddr;
static u64 last_pfn;
static u64 hits;

/* per-probe-instance stash */
struct dw_stash {
	pte_t   *ptep;       /* leaf slot (only used for a validity marker) */
	pte_t    saved;      /* value seen on entry (present, old PFN) */
	unsigned long vaddr;
	bool     valid;
};

/*
 * Walk mm's page tables to the leaf slot for vaddr. Uses pte_offset_kernel
 * (raw pointer arithmetic; no kmap/RCU machinery -> no ___pte_offset_map dep,
 * fine on x86-64 where page tables are always mapped). No unmap needed. On
 * success *pmdp is the pmd so the caller can take the pte lock.
 */
static pte_t *walk_leaf(struct mm_struct *mm, unsigned long vaddr, pmd_t **pmdp)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, vaddr);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
		dw_dbg("walk: pgd none/bad\n"); return NULL;
	}
	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d))) {
		dw_dbg("walk: p4d none/bad\n"); return NULL;
	}
	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)) || pud_leaf(*pud)) {
		dw_dbg("walk: pud none/bad/leaf (leaf=%d)\n", pud_leaf(*pud)); return NULL;
	}
	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)) || pmd_leaf(*pmd)) {
		dw_dbg("walk: pmd none=%d bad=%d leaf=%d\n",
		       pmd_none(*pmd), pmd_bad(*pmd), pmd_leaf(*pmd)); return NULL;
	}

	*pmdp = pmd;
	return pte_offset_kernel(pmd, vaddr);
}

static int dw_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct dw_stash *s = (struct dw_stash *)ri->data;
	struct mm_struct *mm = current->mm;
	unsigned long vaddr = READ_ONCE(armed_vaddr);
	pmd_t *pmd;
	pte_t *pte, val;

	s->valid = false;
	if (!vaddr || mm != READ_ONCE(target_mm))
		return 1; /* not our target -> skip return handler */

	pte = walk_leaf(mm, vaddr, &pmd);
	if (!pte) {
		dw_dbg("entry: walk_leaf failed for vaddr=%px\n", (void *)vaddr);
		return 1;
	}

	val = ptep_get(pte);
	dw_dbg("entry: vaddr=%px pte=%lx present=%d pfn=%lx\n",
	       (void *)vaddr, pte_val(val), pte_present(val),
	       pte_present(val) ? pte_pfn(val) : 0);

	if (!pte_present(val))
		return 1; /* nothing to preserve */

	s->saved = val;
	s->vaddr = vaddr;
	s->valid = true;
	return 0; /* run return handler */
}

static int dw_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct dw_stash *s = (struct dw_stash *)ri->data;
	struct mm_struct *mm = current->mm;
	pmd_t *pmd;
	pte_t *pte, now;
	spinlock_t *ptl;

	if (!s->valid)
		return 0;

	/* Re-derive the slot; the leaf page-table page survives thanks to the
	 * <2MB remap trick, but re-walk defensively rather than trusting a
	 * stale pointer. Take the pte lock this time since the zap dropped it. */
	pte = walk_leaf(mm, s->vaddr, &pmd);
	if (!pte)
		return 0;
	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);

	now = ptep_get(pte);
	dw_dbg("ret:   vaddr=%px now=%lx present=%d none=%d\n",
	       (void *)s->vaddr, pte_val(now), pte_present(now), pte_none(now));
	/* Only re-stamp if the teardown actually cleared it (i.e. this call was
	 * the one covering our vaddr). If still present, this call didn't touch
	 * it -> leave armed for the real one. */
	if (pte_none(now) || !pte_present(now)) {
		set_pte_at(mm, s->vaddr, pte, s->saved);
		WRITE_ONCE(last_vaddr, s->vaddr);
		WRITE_ONCE(last_pfn, (u64)pte_pfn(s->saved));
		WRITE_ONCE(hits, hits + 1);
		WRITE_ONCE(armed_vaddr, 0); /* one-shot: disarm */
		spin_unlock(ptl);
		/* deliberately NO tlb flush: mirror a dropped write; the CPU may
		 * still hold a stale/valid TLB entry either way. */
		pr_info("dropped zap store at vaddr=%px pfn=%llx (mm=%px)\n",
			(void *)s->vaddr, (u64)pte_pfn(s->saved), mm);
		return 0;
	}

	spin_unlock(ptl);
	return 0;
}

static struct kretprobe dw_krp = {
	/* unmap_page_range() is the function that actually walks + clears the
	 * leaf PTEs and tears down the pages (zap_pte_range is inlined into it:
	 * ptep_get_and_clear + folio_remove_rmap + tlb free). On entry the old
	 * PTE is present; on return it's cleared AND the page freed. We restore
	 * the saved value here, before free_pgtables() runs in the "complete"
	 * phase -- the surviving last page (SZ-0x1000 trick) keeps the leaf
	 * pte-page alive, and our restored entry keeps the pmd non-empty so
	 * free_pgtables leaves it be. Net: present PTE -> freed page == UAF. */
	.kp.symbol_name    = "unmap_page_range",
	.entry_handler     = dw_entry,
	.handler           = dw_ret,
	.data_size         = sizeof(struct dw_stash),
	.maxactive         = 64,
};

/* debugfs "arm": capture target mm = writer's mm, store vaddr */
static ssize_t arm_write(struct file *f, const char __user *ubuf,
			 size_t len, loff_t *off)
{
	char kbuf[32];
	unsigned long v;

	if (len == 0 || len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	if (kstrtoul(strim(kbuf), 0, &v))
		return -EINVAL;

	if (v) {
		WRITE_ONCE(target_mm, current->mm);
		WRITE_ONCE(armed_vaddr, v);
		pr_info("armed vaddr=%px for mm=%px (comm=%s pid=%d)\n",
			(void *)v, current->mm, current->comm, current->pid);
	} else {
		WRITE_ONCE(armed_vaddr, 0);
		WRITE_ONCE(target_mm, NULL);
		pr_info("disarmed\n");
	}
	return len;
}

static const struct file_operations arm_fops = {
	.owner = THIS_MODULE,
	.write = arm_write,
};

static int __init dw_init(void)
{
	int ret;

	ret = register_kretprobe(&dw_krp);
	if (ret) {
		pr_err("register_kretprobe(vms_clear_ptes) failed: %d\n", ret);
		return ret;
	}

	ddir = debugfs_create_dir("dropwrite", NULL);
	/* world-writable on purpose: dev fault-injector usable from the
	 * unprivileged exploit process. */
	debugfs_create_file("arm", 0222, ddir, NULL, &arm_fops);
	debugfs_create_u64("last_vaddr", 0444, ddir, &last_vaddr);
	debugfs_create_u64("last_pfn", 0444, ddir, &last_pfn);
	debugfs_create_u64("hits", 0444, ddir, &hits);

	pr_info("loaded; kretprobe @ %p\n", dw_krp.kp.addr);
	return 0;
}

static void __exit dw_exit(void)
{
	unregister_kretprobe(&dw_krp);
	debugfs_remove_recursive(ddir);
	pr_info("unloaded (hits=%llu)\n", hits);
}

module_init(dw_init);
module_exit(dw_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("deterministic dropped-zap-store PTE fault injector");
