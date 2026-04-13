// Phase 12: API Documentation Discovery — OpenAPI/Swagger/GraphQL/WSDL.

const { URL } = require('url');
const { loadConfig, writeArtifact, fetchWithTimeout, log, canonicalizePath } = require('./lib');

const SPEC_PATHS = [
  '/swagger.json', '/swagger/v1/swagger.json', '/v2/api-docs', '/v3/api-docs',
  '/openapi.json', '/openapi.yaml', '/openapi/v1.json',
  '/api-docs', '/api/docs', '/api/swagger.json',
  '/swagger-ui.html', '/swagger-ui/index.html',
  '/graphql', '/api/graphql', '/v1/graphql', '/graphiql',
  '/wsdl', '/?wsdl', '/service?wsdl',
];

const INTROSPECTION_QUERY = JSON.stringify({
  query: `{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }`,
});

function parseOpenAPI(spec) {
  const endpoints = [];
  const paths = spec.paths || {};
  for (const [p, methods] of Object.entries(paths)) {
    for (const method of Object.keys(methods)) {
      if (['get', 'post', 'put', 'patch', 'delete', 'options', 'head'].includes(method.toLowerCase())) {
        endpoints.push({
          path: p,
          canonical: canonicalizePath(p.replace(/\{[^}]+\}/g, ':id')),
          method: method.toUpperCase(),
          summary: methods[method].summary || null,
        });
      }
    }
  }
  return endpoints;
}

(async () => {
  const cfg = loadConfig();
  const target = cfg.target.replace(/\/$/, '');
  log(12, `probing ${SPEC_PATHS.length} spec paths`);

  const results = {
    phase: 12,
    timestamp: new Date().toISOString(),
    specs: [],
    graphqlFound: false,
    graphqlSchema: null,
    endpoints: [],
  };

  for (const p of SPEC_PATHS) {
    const url = target + p;
    try {
      const res = await fetchWithTimeout(url, { method: 'GET' }, 8000);
      if (!res.ok) continue;
      const ct = res.headers.get('content-type') || '';
      if (ct.includes('json')) {
        const body = await res.json();
        if (body.swagger || body.openapi) {
          const eps = parseOpenAPI(body);
          results.specs.push({ url, type: body.openapi ? 'openapi' : 'swagger', version: body.openapi || body.swagger, endpointCount: eps.length });
          results.endpoints.push(...eps.map(e => ({ ...e, discoveredBy: 'api-spec', sourceUrl: url })));
          log(12, `  ${p}: OpenAPI/Swagger with ${eps.length} endpoints`);
        }
      } else if (p.includes('graphql')) {
        results.graphqlFound = true;
        // Try introspection
        try {
          const introRes = await fetchWithTimeout(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: INTROSPECTION_QUERY,
          }, 10000);
          if (introRes.ok) {
            const introJson = await introRes.json();
            if (introJson.data?.__schema) {
              results.graphqlSchema = {
                url,
                types: (introJson.data.__schema.types || []).map(t => ({ name: t.name, kind: t.kind, fieldCount: (t.fields || []).length })),
                queryType: introJson.data.__schema.queryType?.name,
                mutationType: introJson.data.__schema.mutationType?.name,
              };
              results.endpoints.push({ path: p, canonical: canonicalizePath(p), method: 'POST', discoveredBy: 'graphql-introspection', sourceUrl: url });
              log(12, `  ${p}: GraphQL introspection OK (${results.graphqlSchema.types.length} types)`);
            }
          }
        } catch {}
      } else {
        results.specs.push({ url, type: 'ui-page', status: res.status });
      }
    } catch {}
  }

  writeArtifact('phase12_apidocs.json', results);
  log(12, `OK: ${results.specs.length} specs, ${results.endpoints.length} endpoints from specs`);
})();
