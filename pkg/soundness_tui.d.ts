/* tslint:disable */
/* eslint-disable */
export function parse_cli_command(command: string): any;
export function get_version(): string;
export function start_app(): void;
export function list_keys(): any;
export function generate_key_pair(name: string, password: string): Promise<any>;
export function import_phrase(phrase: string, name: string, password: string): Promise<any>;
export function send_proof(proof_blob_id: string, key_name: string, proving_system: string, game: string | null | undefined, payload: string | null | undefined, elf_file: string | null | undefined, password: string): Promise<any>;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly parse_cli_command: (a: number, b: number) => [number, number, number];
  readonly get_version: () => [number, number];
  readonly start_app: () => void;
  readonly list_keys: () => [number, number, number];
  readonly generate_key_pair: (a: number, b: number, c: number, d: number) => any;
  readonly import_phrase: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
  readonly send_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number) => any;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_4: WebAssembly.Table;
  readonly __externref_drop_slice: (a: number, b: number) => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_export_7: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly closure55_externref_shim: (a: number, b: number, c: any) => void;
  readonly closure59_externref_shim: (a: number, b: number, c: any) => void;
  readonly closure29_externref_shim: (a: number, b: number, c: any, d: any) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
