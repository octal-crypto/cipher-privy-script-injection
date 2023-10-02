import TerserPlugin from "terser-webpack-plugin";

export default {
    entry: './script.js',
    output: { path: process.cwd(), filename: 'dist.js' },
    optimization: {
        minimizer: [new TerserPlugin({
            extractComments: false,
            terserOptions: { format: { comments: false } },
        })],
    },
}
