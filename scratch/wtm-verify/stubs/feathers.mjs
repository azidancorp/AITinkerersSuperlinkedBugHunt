// Synthetic offline stand-in for @feathersjs/client.
// The real app.js does: feathers(); feathers.rest(url); app.configure(...);
// app.service(name).create(payload) / .get(id).
// Every service call is recorded on globalThis.__feathersServiceCalls so
// harnesses can observe whether a feathers write actually happened.
const calls = [];
globalThis.__feathersServiceCalls = calls;

const app = {
  configure: (..._args) => app,
  service: (name) => ({
    create: (payload) => {
      calls.push({ method: "create", service: name, payload });
      return Promise.resolve({ id: "synthetic-id" });
    },
    get: (id) => {
      calls.push({ method: "get", service: name, id });
      return Promise.resolve({ country: "de" });
    },
  }),
};

const feathers = () => app;
feathers.rest = (_url) => ({
  fetch: (_fetchImpl, _opts) => (() => {}),
});

export default feathers;
