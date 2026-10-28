/** Adapter injected with Baileys serializers so offline tests do not open WhatsApp. */
export function createSqliteAuthState(store, { BufferJSON, initAuthCreds, proto }) {
  const decode = value => value === undefined ? undefined : JSON.parse(value, BufferJSON.reviver);
  const encode = value => JSON.stringify(value, BufferJSON.replacer);
  const creds = decode(store.authGet('credentials', 'primary')) ?? initAuthCreds();
  const saveCreds = (update = {}) => {
    Object.assign(creds, update);
    store.authBatch([{ category: 'credentials', id: 'primary', value: encode(creds) }]);
  };
  saveCreds();

  return {
    state: {
      creds,
      keys: {
        async get(category, ids) {
          const result = Object.create(null);
          for (const id of ids) {
            let value = decode(store.authGet(`key:${category}`, id));
            if (category === 'app-state-sync-key' && value) {
              value = proto.Message.AppStateSyncKeyData.fromObject(value);
            }
            result[id] = value;
          }
          return result;
        },
        async set(data) {
          const entries = [];
          for (const [category, records] of Object.entries(data)) {
            for (const [id, value] of Object.entries(records ?? {})) {
              entries.push({ category: `key:${category}`, id, value: value == null ? null : encode(value) });
            }
          }
          store.authBatch(entries);
        }
      }
    },
    saveCreds
  };
}
