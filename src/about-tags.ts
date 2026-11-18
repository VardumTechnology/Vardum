/**
 * b77k (IP77-1, iPhone battery): the wire tag Settings → About shows, derived from the protocol
 * constant the ratchet engine stamps into every header (crypto-core RATCHET_PROTOCOL_LATEST), so
 * it can't drift again (it said veil-ratchet-4 on a veil-ratchet-8 build). Pure: no React Native.
 */
import { RATCHET_PROTOCOL_LATEST } from '../vendor/crypto-core/src/constants';

export const PROTOCOL_WIRE_TAG = `wire tag: ${RATCHET_PROTOCOL_LATEST} · PQ-hybrid`;
