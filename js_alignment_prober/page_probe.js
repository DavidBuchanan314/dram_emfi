function page_probe(ab32, progress_cb, done_cb)
{
	const MAX_DETECTABLE_CACHE_LINE_SIZE = 4096 * 8; // in bytes

	const num_groups = MAX_DETECTABLE_CACHE_LINE_SIZE / 64; // each "lane" is 64 bytes wide
	const num_steps = Math.floor((ab32.byteLength - (16 + 1)*4) / 64 / num_groups);
	let permutation = Array.from(Array(num_steps).keys()); // https://stackoverflow.com/a/33352604
	shuffleArray(permutation);
	permutation.push(permutation[0]);

	// fill in the big array
	for (let i=0; i<num_steps; i++) {
		let a = permutation[i];
		let b = permutation[i+1];
		for (let j=0; j<num_groups; j++) {
			ab32[(a * num_groups + j) * 8 * 2 + 0] = b;
			ab32[(a * num_groups + j) * 8 * 2 + 1] = 0;
		}
	}

	console.log("starting");

	function microbench(offset, steps) {
		let start = performance.now();

		let ptr = 0;
		for (let i=0; i<steps; i++) {
			let x = (ptr * num_groups + offset) * 8 * 2;
			ptr = ab32[x + ab32[x + 8 * 2 + 1]]; // always two cache lines but sometimes two pages
		}

		return performance.now() - start;
	}

	// maybe warm up the JIT
	//for (let i=0; i<1000; i++) {
	//	microbench(0, 100);
	//}

	let results = new Array(num_groups).fill(0);

	function bench_step(repeats, offset)
	{
		if(offset >= num_groups) {
			repeats += 1;
			offset = 0;
			if (repeats > 2) {
				//alert("done");
				let res = process_cache_line_search_results();
				if (typeof res === "string") {
					done_cb(null, null, res);
				} else {
					done_cb(res[0], res[1]);
				}
				return;
			}
		};
		let duration = microbench(offset, 1000000); // bench needs to be slow enough to measure with ms resolution
		//results.push(duration);
		results[offset] = results[offset] == 0 ? duration : Math.min(results[offset], duration);
		//console.log(offset, duration);

		//plot_graph(c, results);
		progress_cb(results, Array.from(results.keys()).map(x=>x*8*8));

		setTimeout(()=>bench_step(repeats, offset+1), 0); // yield
	}

	function process_cache_line_search_results()
	{
		const threshold = (Math.min(...results) + Math.max(...results)) / 2;
		let slow_result_indices = [];
		for (let i in results) {
			if (results[i] > threshold) {
				slow_result_indices.push(i*1); // omg i is a string by default I hate JS so much
			}
		}
		if (slow_result_indices.length & (slow_result_indices.length - 1)) { // if not a power of 2
			return "Error: Failed to determine cache line size!";
		}
		let spacing = results.length / slow_result_indices.length;
		for (let i of slow_result_indices) {
			if ((i % spacing) != (slow_result_indices[0] % spacing)) {
				return "Error: Failed to determine cache line size!";
			}
		}
		const cache_line_size_bytes = spacing * 8 * 8;
		console.log(slow_result_indices, spacing);
		const cache_line_offset = ((slow_result_indices[0] + 1) % spacing) * 8 * 8; // XXX: probably wrong lol
		console.log(cache_line_offset);
		return [cache_line_offset, cache_line_size_bytes];
		/*msg = "Detected cache line size: " + cache_line_size_bytes + " bytes."
		console.log(msg);
		let p = document.createElement("p");
		p.innerText = msg;
		document.body.appendChild(p);*/
	}

	bench_step(0, 0);
}
