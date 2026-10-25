/**
 * Resolve once the browser has painted the current state.
 *
 * Key generation runs in the wasm module on this thread and holds it for
 * as long as it takes -- seconds for RSA-4096. Started in the same tick
 * as the state change that shows "Generating…", the panel never gets to
 * draw that screen and just sits frozen on the button that was pressed.
 * Awaiting this between the two lets the progress screen land first; its
 * spinner is a compositor animation, so it keeps turning while the main
 * thread is busy.
 */
export function afterNextPaint(): Promise<void> {
  return new Promise((resolve) => {
    requestAnimationFrame(() => setTimeout(resolve, 0));
  });
}
