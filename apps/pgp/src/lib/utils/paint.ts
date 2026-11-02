/** Resolve once the current state has painted. Await before blocking
 *  main-thread wasm work (e.g. RSA keygen) so the progress screen shows. */
export function afterNextPaint(): Promise<void> {
  return new Promise((resolve) => {
    requestAnimationFrame(() => setTimeout(resolve, 0));
  });
}
