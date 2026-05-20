<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let title = '';
  export let titleId = 'modal-title';

  const dispatch = createEventDispatcher<{ close: void }>();

  function close() {
    dispatch('close');
  }

  function handleKeydown(event: KeyboardEvent) {
    if (event.key !== 'Escape') {
      return;
    }
    event.preventDefault();
    close();
  }
</script>

<svelte:window on:keydown={handleKeydown} />

<div class="modal-backdrop" role="presentation" on:pointerdown={close}>
  <div
    class="modal-card"
    role="dialog"
    aria-modal="true"
    aria-labelledby={titleId}
    tabindex="-1"
    on:pointerdown|stopPropagation
  >
    <div class="modal-header">
      <h3 id={titleId}>{title}</h3>
      <button type="button" class="small-button" on:click={close}>
        Done
      </button>
    </div>

    <div class="modal-body">
      <slot />
    </div>
  </div>
</div>
