import type { VcrTransport } from './types';

/** Declares a typed `VcrTransport` implementation for custom protocols (SQL, RPC, SDKs, etc.). */
export const defineVcrTransport = <TRequest, TResponse>(
  transport: VcrTransport<TRequest, TResponse>,
): VcrTransport<TRequest, TResponse> => transport;
