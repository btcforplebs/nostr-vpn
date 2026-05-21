<script lang="ts">
  import { createEventDispatcher, onDestroy } from 'svelte';

  type ButtonVariant = 'small' | 'secondary';

  export let value = '';
  export let label = 'Value';
  export let text = '';
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
  class:with-text={Boolean(text)}
  class:copied
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
  {#if text}
    <span>{text}</span>
  {/if}
</button>

<style>
  .copy-button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: 0 0 auto;
    gap: 7px;
    border: 1px solid var(--border, rgba(255, 255, 255, 0.12));
    border-radius: 8px;
    color: var(--text-primary, #f5f5f7);
    background: var(--control, #2c2c2e);
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

  .copy-button.with-text {
    width: auto;
    min-width: 0;
    padding: 0 12px;
  }

  .copy-button:not(:disabled):hover {
    background: var(--control-hover, #363638);
  }

  .copy-button.copied {
    border-color: transparent;
    color: var(--ok, #30d158);
    background: var(--ok-soft, rgba(48, 209, 88, 0.16));
  }

  .copy-button svg {
    width: 16px;
    height: 16px;
    fill: currentColor;
  }
</style>
