// Unified connector entry point.
// Returns a normalized server snapshot:
//   { name, version, transport, auth, url, tools, resources, prompts, capabilities }

import { connectStdio } from './stdio.js';
import { connectHttp } from './http.js';
import { loadManifest } from './manifest.js';

export async function connect(spec) {
  if (spec.manifest) return loadManifest(spec.manifest);
  if (spec.stdio) return connectStdio(spec.stdio, spec);
  if (spec.url) return connectHttp(spec.url, spec);
  throw new Error('connect: provide one of { stdio, url, manifest }');
}
