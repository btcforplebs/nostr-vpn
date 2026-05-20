<script lang="ts">
  import { createEventDispatcher, onDestroy } from 'svelte';

  type ButtonVariant = 'small' | 'secondary';

  export let value = '';
  export let label = 'Value';
  export let disabled = false;
  export let variant: ButtonVariant = 'small';

  const dispatch = createEventDispatcher<{ copied: { label: string; value: string } }>();

  let copied = false;
  let copiedTimer: number | undefined;

  onDestroy(() => {
    if (copiedTimer) {
      window.clearTimeout(copiedTimer);
    }
  });

  async function writeClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const area = document.createElement('textarea');
      area.value = text;
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.append(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
  }

  async function copy() {
    if (disabled || !value) {
      return;
    }

    await writeClipboard(value);
    copied = true;
    dispatch('copied', { label, value });

    if (copiedTimer) {
      window.clearTimeout(copiedTimer);
    }
    copiedTimer = window.setTimeout(() => {
      copied = false;
      copiedTimer = undefined;
    }, 2000);
  }
</script>

<button
  type="button"
  class="copy-button {variant}"
  disabled={disabled || !value}
  aria-label={copied ? `${label} copied` : `Copy ${label}`}
  title={copied ? 'Copied' : `Copy ${label}`}
  on:click={copy}
>
  {#if copied}
    <svg aria-hidden="true" viewBox="0 0 16 16" focusable="false">
      <path d="M6.7 11.4 3.3 8l1.1-1.1 2.3 2.3 4.9-4.9L12.7 5z" />
    </svg>
  {:else}
    <svg aria-hidden="true" viewBox="0 0 16 16" focusable="false">
      <path d="M5 2.5h7.5V10H11V4H5z" />
      <path d="M3.5 5H10v8.5H3.5z" />
    </svg>
  {/if}
</button>

<style>
  .copy-button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: 0 0 auto;
    border: 0;
    border-radius: 8px;
    color: #11140f;
    background: #d7b46a;
    font-weight: 700;
  }

  .copy-button.small {
    width: 34px;
    min-height: 34px;
  }

  .copy-button.secondary {
    width: 40px;
    min-height: 40px;
  }

  .copy-button:hover {
    filter: brightness(1.06);
  }

  .copy-button svg {
    width: 16px;
    height: 16px;
    fill: currentColor;
  }
</style>
