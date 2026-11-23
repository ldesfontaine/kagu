import { useState, type ComponentProps, type ReactNode } from "react";

import { Button } from "./Button";
import type { IconName } from "./Icon";
import { Modal, ModalCancel } from "./Modal";

// La question d'un geste qui ne se défait pas (supprimer, régénérer un jeton,
// remplacer une clé), dans une fenêtre qui nomme la conséquence. Ce qui se
// défait reste à ConfirmInline, plus léger. onConfirm part dès le clic et la
// fenêtre se ferme : l'écriture et son erreur restent à la page (useAction),
// comme avec ConfirmInline. Contrôlée par l'appelant quand le geste n'est pas
// un bouton (un envoi de formulaire) ; ConfirmModal en est le bouton.
// Avec stays, la fenêtre reste ouverte au clic : ce qu'elle demande en plus
// (children, un mot de passe par exemple) se juge avant le geste, et
// l'appelant la ferme quand il a abouti, ou y montre le refus.
export function ConfirmDialog({
  title,
  question,
  confirmLabel,
  onConfirm,
  onClose,
  stays = false,
  busy = false,
  dirty = false,
  children,
}: {
  title: string;
  question: string;
  confirmLabel: string;
  onConfirm: () => void;
  onClose: () => void;
  stays?: boolean;
  busy?: boolean;
  dirty?: boolean;
  children?: ReactNode;
}) {
  const confirm = () => {
    if (!stays) {
      onClose();
    }
    onConfirm();
  };
  return (
    <Modal
      title={title}
      onClose={onClose}
      dirty={dirty}
      actions={
        <>
          <ModalCancel />
          <Button variant="danger" onClick={confirm} disabled={busy}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <p className="modal-question">{question}</p>
      {children}
    </Modal>
  );
}

// Un bouton qui ouvre la confirmation. Même forme que ConfirmInline :
// l'appelant change de balise, pas de logique.
export function ConfirmModal({
  title,
  question,
  confirmLabel,
  onConfirm,
  variant = "secondary",
  small = false,
  icon,
  disabled = false,
  children,
}: {
  title: string;
  question: string;
  confirmLabel: string;
  onConfirm: () => void;
  variant?: ComponentProps<typeof Button>["variant"];
  small?: boolean;
  icon?: IconName;
  disabled?: boolean;
  // Le libellé du bouton qui ouvre la fenêtre.
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button variant={variant} small={small} {...(icon !== undefined && { icon })} disabled={disabled} onClick={() => setOpen(true)}>
        {children}
      </Button>
      {open && <ConfirmDialog title={title} question={question} confirmLabel={confirmLabel} onConfirm={onConfirm} onClose={() => setOpen(false)} />}
    </>
  );
}
