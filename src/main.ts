/**
 * Copyright @stephane-lambou
 */

import './style.css'
import viteLogo from '/vite.svg'
import {main} from "./lib.ts";

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <div class="container mx-auto px-4 py-8 flex flex-col items-center gap-4">
    <a href="/" target="_blank">
      <img src="${viteLogo}" class="logo" alt="Vite logo" />
    </a>
    <h1>WebAuthn PRF tests</h1>
    <div class="flex flex-row gap-4">
      <button id="registerBtn" type="button" class="btn btn-primary btn-soft">
        Register
      </button>
      <button id="authenticateBtn" type="button" class="btn btn-primary btn-soft">
        Authenticate
      </button>
    </div>
    <div class="w-full overflow-scroll" id="error"></div>
  </div>
`

main().catch(console.error);