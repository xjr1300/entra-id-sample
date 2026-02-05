// プロファイル
export interface Profile {
  id?: string | null;
  userPrincipalName?: string | null;
  surname?: string | null;
  givenName?: string | null;
  displayName?: string | null;
  mail?: string | null;
  jobTitle?: string | null;
  department?: string | null;
  officeLocation?: string | null;
  businessPhones?: string[] | null;
  mobilePhone?: string | null;
  preferredLanguage?: string | null;
}

// Profile型ガード
export const isProfile = (obj: unknown): obj is Profile => {
  if (typeof obj != 'object' || obj === null) return false;
  const instance = obj as Profile;
  if (instance.id != null && typeof instance.id !== 'string') return false;
  if (
    instance.userPrincipalName != null &&
    typeof instance.userPrincipalName !== 'string'
  )
    return false;
  if (instance.displayName != null && typeof instance.displayName !== 'string')
    return false;
  if (instance.surname != null && typeof instance.surname !== 'string')
    return false;
  if (instance.givenName != null && typeof instance.givenName !== 'string')
    return false;
  if (instance.jobTitle != null && typeof instance.jobTitle !== 'string')
    return false;
  if (instance.mail != null && typeof instance.mail !== 'string') return false;
  if (instance.department != null && typeof instance.department !== 'string')
    return false;
  if (
    instance.officeLocation != null &&
    typeof instance.officeLocation !== 'string'
  )
    return false;
  if (instance.businessPhones != null) {
    if (!Array.isArray(instance.businessPhones)) return false;
    for (const phone of instance.businessPhones) {
      if (typeof phone !== 'string') return false;
    }
  }
  if (instance.mobilePhone != null && typeof instance.mobilePhone !== 'string')
    return false;
  if (
    instance.preferredLanguage != null &&
    typeof instance.preferredLanguage !== 'string'
  )
    return false;
  return true;
};
