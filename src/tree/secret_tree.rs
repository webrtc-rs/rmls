use bytes::Bytes;

use crate::cipher_suite::*;
use crate::error::*;
use crate::framing::*;
use crate::tree::tree_math::*;

pub(crate) type RatchetLabel = Bytes;

pub(crate) static RATCHET_LABEL_HANDSHAKE: Bytes = Bytes::from_static(b"handshake");
pub(crate) static RATCHET_LABEL_APPLICATION: Bytes = Bytes::from_static(b"application");

fn ratchet_label_from_content_type(ct: ContentType) -> Result<RatchetLabel> {
    match ct {
        ContentType::Application => Ok(RATCHET_LABEL_APPLICATION.clone()),
        ContentType::Proposal | ContentType::Commit => Ok(RATCHET_LABEL_HANDSHAKE.clone()),
    }
}

// secretTree holds tree node secrets used for the generation of encryption
// keys and nonces.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct SecretTree(pub(crate) Vec<Option<Bytes>>);

fn derive_secret_tree(
    cs: CipherSuite,
    n: NumLeaves,
    encryption_secret: Bytes,
) -> Result<SecretTree> {
    let mut tree = SecretTree(vec![None; n.width() as usize]);
    tree.set(n.root(), encryption_secret);
    tree.derive_children(cs, n.root())?;
    Ok(tree)
}

impl SecretTree {
    fn derive_children(&self, _cs: CipherSuite, x: NodeIndex) -> Result<()> {
        let (_l, _r, ok) = x.children();
        if !ok {
            return Ok(());
        }
        /*TODO(yngrtc):
        parentSecret := tree.get(x)
        _, kdf, _ := cs.hpke().Params()
        nh := uint16(kdf.ExtractSize())
        leftSecret, err := cs.expandWithLabel(parentSecret, []byte("tree"), []byte("left"), nh)
        if err != nil {
            return err
        }
        rightSecret, err := cs.expandWithLabel(parentSecret, []byte("tree"), []byte("right"), nh)
        if err != nil {
            return err
        }

        tree.set(l, leftSecret)
        tree.set(r, rightSecret)

        if err := tree.deriveChildren(cs, l); err != nil {
            return err
        }
        if err := tree.deriveChildren(cs, r); err != nil {
            return err
        }*/

        Ok(())
    }

    fn get(&self, ni: NodeIndex) -> Option<&Option<Bytes>> {
        self.0.get(ni.0 as usize)
    }

    fn set(&mut self, ni: NodeIndex, secret: Bytes) {
        if (ni.0 as usize) < self.0.len() {
            self.0[ni.0 as usize] = Some(secret);
        }
    }

    // deriveRatchetRoot derives the root of a ratchet for a tree node.
    /*TODO(yngrtc):fn deriveRatchetRoot(&self, cs: CipherSuite, ni: NodeIndex, label: &RatchetLabel) ->Result<RatchetSecret> {
        _, kdf, _ := cs.hpke().Params()
        nh := uint16(kdf.ExtractSize())
        root, err := cs.expandWithLabel(tree.get(ni), []byte(label), nil, nh)
        return ratchetSecret{root, 0}, err
    }
    */
}

pub(crate) struct RatchetSecret {
    secret: Bytes,
    generation: u32,
}

/*
impl RatchetSecret  {
    fn deriveNonce(&self, cs: CipherSuite) ->Result<Bytes> {
        _, _, aead := cs.hpke().Params()
        nn := uint16(aead.NonceSize())
        return deriveTreeSecret(cs, secret.secret, []byte("nonce"), secret.generation, nn)
    }

    fn deriveKey(cs cipherSuite) ([]byte, error) {
        _, _, aead := cs.hpke().Params()
        nk := uint16(aead.KeySize())
        return deriveTreeSecret(cs, secret.secret, []byte("key"), secret.generation, nk)
    }

    fn deriveNext(cs cipherSuite) (ratchetSecret, error) {
        _, kdf, _ := cs.hpke().Params()
        nh := uint16(kdf.ExtractSize())
        next, err := deriveTreeSecret(cs, secret.secret, []byte("secret"), secret.generation, nh)
        return ratchetSecret{next, secret.generation + 1}, err
    }

}

fn deriveTreeSecret(cs cipherSuite, secret, label []byte, generation uint32, length uint16) ([]byte, error) {
    var b cryptobyte.Builder
    b.AddUint32(generation)
    context := b.BytesOrPanic()

    return cs.expandWithLabel(secret, label, context, length)
}
*/
