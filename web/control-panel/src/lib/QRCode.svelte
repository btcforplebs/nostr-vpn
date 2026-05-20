<script lang="ts">
  export let data = '';
  export let size = 186;

  let qrCodeUrl = '';
  let qrError = false;
  let generation = 0;

  async function generateQr(value: string, width: number) {
    const currentGeneration = ++generation;
    qrCodeUrl = '';
    qrError = false;

    if (!value) {
      return;
    }

    try {
      const QRCode = await import('qrcode');
      const url = await QRCode.toDataURL(value, {
        width,
        margin: 0,
        color: {
          dark: '#000000',
          light: '#ffffff',
        },
      });
      if (currentGeneration === generation) {
        qrCodeUrl = url;
      }
    } catch {
      if (currentGeneration === generation) {
        qrError = true;
      }
    }
  }

  $: void generateQr(data, size);
</script>

{#if qrCodeUrl}
  <img class="qr-image" src={qrCodeUrl} alt="Invite QR code" width={size} height={size} />
{:else}
  <div class="qr-empty">{qrError ? 'QR unavailable' : 'QR'}</div>
{/if}
