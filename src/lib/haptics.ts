import { Capacitor } from '@capacitor/core';

let _hapticsEnabled = true;

/** Call this from the app when settings load/change */
export function setHapticsEnabled(enabled: boolean) {
  _hapticsEnabled = enabled;
}

export async function hapticSuccess() {
  if (!_hapticsEnabled) return;
  try {
    if (Capacitor.isNativePlatform()) {
      const { Haptics, NotificationType } = await import('@capacitor/haptics');
      await Haptics.notification({ type: NotificationType.Success });
    } else if (typeof navigator !== 'undefined' && 'vibrate' in navigator) {
      navigator.vibrate([30, 50, 30]);
    }
  } catch { /* non-critical */ }
}

export async function hapticImpact() {
  if (!_hapticsEnabled) return;
  try {
    if (Capacitor.isNativePlatform()) {
      const { Haptics, ImpactStyle } = await import('@capacitor/haptics');
      await Haptics.impact({ style: ImpactStyle.Medium });
    } else if (typeof navigator !== 'undefined' && 'vibrate' in navigator) {
      navigator.vibrate(50);
    }
  } catch { /* non-critical */ }
}

export async function hapticLight() {
  if (!_hapticsEnabled) return;
  try {
    if (Capacitor.isNativePlatform()) {
      const { Haptics, ImpactStyle } = await import('@capacitor/haptics');
      await Haptics.impact({ style: ImpactStyle.Light });
    } else if (typeof navigator !== 'undefined' && 'vibrate' in navigator) {
      navigator.vibrate(20);
    }
  } catch { /* non-critical */ }
}
