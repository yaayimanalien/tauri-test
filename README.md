# Daylight UI

Svelte 5 + Vite + Tailwind v4 + shadcn-svelte (bits-ui). UI only: entries are mock data in
`src/lib/journal.svelte.ts`, which marks where each Tauri command goes.

```bash
npm install
npm run dev          # http://localhost:1420   (add #setup for the first-run screen)
```

## Structure
- `src/app.css` – every colour, glass material, typeface and accent lives in tokens at the top.
  New theme = one `:root[data-theme="…"]` block. New accent = one `[data-accent="…"]` line.
- `src/lib/components/ui/*` – shadcn-svelte primitives (button, input, switch, dialog, context-menu, sonner).
- `src/lib/components/live-editor.svelte` – Obsidian-style live preview.
- `src/lib/components/entry.svelte` – sticky entry header, swipe-right-to-delete, right-click menu.
- `src/lib/components/views/*` – timeline, calendar, stats, settings.
- `src/lib/journal.svelte.ts` – store. Replace the mock seed and the `// backend:` comments with `invoke(...)`.

## Desktop app (Tauri backend merged in)

The Rust backend lives in `src-tauri/` (see `README.backend.md` for encryption, Drive sync and
setup details). The UI talks to it through `src/lib/api.ts`; `journal.svelte.ts` handles autosave,
Drive sync, and the draft lifecycle.

```bash
npm install
npx tauri icon path/to/icon.png   # icons weren't in the zip; generates src-tauri/icons
npm run tauri dev
npm run tauri build
```
