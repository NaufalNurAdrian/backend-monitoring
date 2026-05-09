declare module 'snmp-native' {
  interface SessionOptions {
    host?: string;
    community?: string;
    version?: number;
  }

  interface VarBind {
    oid: string;
    value: any;
  }

  interface GetOptions {
    oid: string;
  }

  interface WalkOptions {
    oid: string;
  }

  class Session {
    constructor(options?: SessionOptions);

    get(
      options: GetOptions,
      callback: (
        err: Error | null,
        varbinds: VarBind[]
      ) => void
    ): void;

    walk(
      options: WalkOptions,
      callback: (
        err: Error | null,
        varbinds: VarBind[]
      ) => void
    ): void;
  }

  const snmp: {
    Session: typeof Session;
  };

  export default snmp;
}