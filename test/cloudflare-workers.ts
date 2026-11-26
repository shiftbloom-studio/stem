// Stand-in for the "cloudflare:workers" runtime module, so tests can run the Worker in Node.
export class WorkerEntrypoint<E = unknown> {
  constructor(protected ctx: ExecutionContext, protected env: E) {}
}
export class DurableObject<E = unknown> {
  constructor(protected ctx: DurableObjectState, protected env: E) {}
}
