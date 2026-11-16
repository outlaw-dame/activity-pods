export interface WebhookChannel {
  id: string;
  topic: string;
  sendTo: string;
  webId: string;
}

export interface AppStatus {
  onlineBackend: boolean;
  installed?: boolean;
  upgradeNeeded?: boolean;
  webhookChannels: WebhookChannel[];
}

export interface Ontology {
  prefix: string;
  owl?: string;
  url: string;
}

export interface PodProvider {
  id?: string;
  type?: string;
  'apods:baseUrl': string;
  'apods:area'?: string;
  'apods:locales'?: string;
  'apods:providedBy'?: string;
}

export interface SolidOIDCToken {
  azp: string;
  sub: string;
  webid: string;
  at_hash: string;
  aud: string;
  exp: number;
  iat: number;
  iss: string;
}
