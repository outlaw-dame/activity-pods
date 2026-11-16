export {};

interface GlobalConfig {
  INSTANCE_NAME: string;
  INSTANCE_DESCRIPTION: object;
  INSTANCE_OWNER: string;
  INSTANCE_AREA: string;
  AVAILABLE_LOCALES: string[];
  DEFAULT_LOCALE: string;
  ENABLE_GROUPS: boolean;
  BACKEND_URL: string;
  MAPBOX_ACCESS_TOKEN: string;
  COLOR_PRIMARY: string;
  COLOR_SECONDARY: string;
}

declare global {
  // A global object property must use var in a TypeScript ambient declaration.
  // eslint-disable-next-line no-var
  var CONFIG: GlobalConfig;
}
