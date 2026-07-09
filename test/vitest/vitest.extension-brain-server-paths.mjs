// Test routing roots for the brain-server extension suite.
export const brainServerExtensionTestRoots = ["extensions/brain-server"];

export function isBrainServerExtensionRoot(root) {
  return brainServerExtensionTestRoots.includes(root);
}
