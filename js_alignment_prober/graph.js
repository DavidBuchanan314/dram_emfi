function plot_graph(c, yvals, xvals) {
	const WIDTH = 720;
	const HEIGHT = 480;
	const MARGIN = 10;
	c.width = WIDTH;
	c.height = HEIGHT;
	const ctx = c.getContext("2d");
	
	ctx.fillStyle = "#fff";
	ctx.fillRect(0, 0, c.width, c.height);
	
	let graph_top = Math.max(...yvals) * 1.1;

	// TODO: have this passed in?
	let threshold = (Math.min(...yvals) + Math.max(...yvals)) / 2;

	for (let i = 0; i < yvals.length; i++) {
		ctx.fillStyle = yvals[i] > threshold ? "red" : "#fff"; // TODO: or maybe just have caller pass colour array?

		let bar_height = yvals[i] / graph_top * (c.height - MARGIN * 2);

		ctx.fillRect(
			MARGIN + (c.width - MARGIN * 2) / yvals.length * i,
			c.height - MARGIN - bar_height,
			(c.width - MARGIN * 2) / yvals.length,
			bar_height
		);

		ctx.strokeRect(
			MARGIN + (c.width - MARGIN * 2) / yvals.length * i,
			c.height - MARGIN - bar_height,
			(c.width - MARGIN * 2) / yvals.length,
			bar_height
		);

		// x axis labels
		if (xvals) {
			ctx.fillStyle = "#000";
			ctx.textAlign = "center";
			ctx.fillText(xvals[i], MARGIN + (c.width - MARGIN * 2) / yvals.length * (i + 0.5), c.height - MARGIN - 10);
		}
	}
}
