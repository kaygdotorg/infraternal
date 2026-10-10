/** Labels only the connection's selected host-key family and its matching public-key command. */
export function hostKeyPresentation(type: string | undefined): { label: string; command: string | undefined } {
  const family = type === "ssh-ed25519" ? { label: "ED25519", file: "ed25519" }
    : type === "ssh-rsa" ? { label: "RSA", file: "rsa" }
    : ["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"].includes(type ?? "") ? { label: "ECDSA", file: "ecdsa" } : undefined;
  return family ? { label: family.label, command: `ssh-keygen -lf /etc/ssh/ssh_host_${family.file}_key.pub` }
    : { label: "Host key", command: undefined };
}
