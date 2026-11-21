import { node } from '@inixiative/config/tsup';

export default node({
  entry: [
    'src/index.ts',
    'src/scrub/index.ts',
    'src/http/index.ts',
    'src/process/index.ts',
    'src/websocket/index.ts',
    'src/freshness/index.ts',
  ],
  minify: true,
  treeshake: true,
  platform: 'node',
});
