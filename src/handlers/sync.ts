import { Env, SyncResponse, CipherResponse, FolderResponse, ProfileResponse } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { cipherToResponse } from './ciphers';

// GET /api/sync
export async function handleSync(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const excludeDomainsParam = url.searchParams.get('excludeDomains');
  const excludeDomains = excludeDomainsParam !== null && /^(1|true|yes)$/i.test(excludeDomainsParam);
  
  const user = await storage.getUserById(userId);
  if (!user) {
    return errorResponse('User not found', 404);
  }

  const ciphers = await storage.getAllCiphers(userId);
  const folders = await storage.getAllFolders(userId);
  const attachmentsByCipher = await storage.getAttachmentsByCipherIds(ciphers.map(c => c.id));

  // Build profile response
  const profile: ProfileResponse = {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: true,
    premium: true,
    premiumFromOrganization: false,
    usesKeyConnector: false,
    masterPasswordHint: null,
    culture: 'en-US',
    twoFactorEnabled: false,
    key: user.key,
    privateKey: user.privateKey,
    accountKeys: null,
    securityStamp: user.securityStamp || user.id,
    organizations: [],
    providers: [],
    providerOrganizations: [],
    forcePasswordReset: false,
    avatarColor: null,
    creationDate: user.createdAt,
    object: 'profile',
  };

  // Build cipher responses with attachments
  const cipherResponses: CipherResponse[] = [];
  for (const cipher of ciphers) {
    const attachments = attachmentsByCipher.get(cipher.id) || [];
    cipherResponses.push(cipherToResponse(cipher, attachments));
  }

  // Build folder responses
  const folderResponses: FolderResponse[] = folders.map(folder => ({
    id: folder.id,
    name: folder.name,
    revisionDate: folder.updatedAt,
    object: 'folder',
  }));

  const syncResponse: SyncResponse = {
    profile: profile,
    folders: folderResponses,
    collections: [],
    ciphers: cipherResponses,
    domains: excludeDomains
      ? null
      : {
          equivalentDomains: [],
          globalEquivalentDomains: [],
          object: 'domains',
        },
    policies: [],
    sends: [],
    // PascalCase for desktop/browser clients
    UserDecryptionOptions: {
      HasMasterPassword: true,
      Object: 'userDecryptionOptions',
      MasterPasswordUnlock: {
        Kdf: {
          KdfType: user.kdfType,
          Iterations: user.kdfIterations,
          Memory: user.kdfMemory || null,
          Parallelism: user.kdfParallelism || null,
        },
        MasterKeyEncryptedUserKey: user.key,
        MasterKeyWrappedUserKey: user.key,
        Salt: user.email.toLowerCase(),
        Object: 'masterPasswordUnlock',
      },
    },
    // camelCase for Android client (SyncResponseJson uses @SerialName("userDecryption"))
    userDecryption: {
      masterPasswordUnlock: {
        kdf: {
          kdfType: user.kdfType,
          iterations: user.kdfIterations,
          memory: user.kdfMemory || null,
          parallelism: user.kdfParallelism || null,
        },
        masterKeyWrappedUserKey: user.key,
        masterKeyEncryptedUserKey: user.key,
        salt: user.email.toLowerCase(),
      },
    },
    object: 'sync',
  };

  return jsonResponse(syncResponse);
}
