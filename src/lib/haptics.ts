import { Capacitor } from '@capacitor/core';

/**
 * Trigger haptic feedback. Works natively in Capacitor (iOS/Android).
 * Falls back to navigator.vibrate on Android browsers.
 * Silently no-ops on iOS Safari (no web haptics API available).
 */
export async function hapticSuccess() {
  try {
    if (Capacitor.isNativePlatform()) {
      const { Haptics, NotificationType } = await import('@capacitor/haptics');
      await Haptics.notification({ type: NotificationType.Success });
    } else if (typeof navigator !== 'undefined' && 'vibrate' in navigator) {
      navigator.vibrate([30, 50, 30]);
    }
  } catch {
    // Silently ignore — haptics are non-critical
  }
}

export async function hapticImpact() {
  try {
    if (Capacitor.isNativePlatform()) {
      const { Haptics, ImpactStyle } = await import('@capacitor/haptics');
      await Haptics.impact({ style: ImpactStyle.Medium });
    } else if (typeof navigator !== 'undefined' && 'vibrate' in navigator) {
      navigator.vibrate(50);
    }
  } catch {
    // Silently ignore
  }
}

export async function hapticLight() {
  try {
    if (Capacitor.isNativePlatform()) {
      const { Haptics, ImpactStyle } = await import('@capacitor/haptics');
      await Haptics.impact({ style: ImpactStyle.Light });
    } else if (typeof navigator !== 'undefined' && 'vibrate' in navigator) {
      navigator.vibrate(20);
    }
  } catch {
    // Silently ignore
  }
}
