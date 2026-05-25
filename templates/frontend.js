document.addEventListener('DOMContentLoaded', () => {
const state = {
      file: null,
      isProcessing: false,
      pendingStoredName: null,
      pendingOriginalName: null,
      pendingModelName: null,
      pendingReferenceProvider: null,
      lastCompletedDownload: null
    };

    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const dropZoneContent = document.getElementById('dropZoneContent');
    const filePreview = document.getElementById('filePreview');
    const selectedFileName = document.getElementById('selectedFileName');
    const selectedFileSize = document.getElementById('selectedFileSize');
    const removeFile = document.getElementById('removeFile');
    const submitBtn = document.getElementById('submitBtn');
    const btnSpinner = document.getElementById('btnSpinner');
    const btnIcon = document.getElementById('btnIcon');
    const btnText = document.getElementById('btnText');
    const statusArea = document.getElementById('statusArea');
    const statusTitle = document.getElementById('statusTitle');
    const statusDesc = document.getElementById('statusDesc');
    const serverState = document.getElementById('serverState');
    const modelNameInput = document.getElementById('modelName');
    const referenceProviderInput = document.getElementById('referenceProvider');
    const startPageInput = document.getElementById('startPage');
    const endPageInput = document.getElementById('endPage');
    const skipEnrichmentInput = document.getElementById('skipEnrichment');
    const enrichmentRow = document.getElementById('enrichmentRow');
    const costModal = document.getElementById('costModal');
    const costConfirmBtn = document.getElementById('costConfirmBtn');
    const costCancelBtn = document.getElementById('costCancelBtn');
    const downloadsList = document.getElementById('downloadsList');
    const refreshDownloadsBtn = document.getElementById('refreshDownloadsBtn');

    if (window.lucide) window.lucide.createIcons();

    const FALLBACK_MODELS = [
      { id: 'gemini-3-flash-preview', label: 'Gemini 3 Flash Preview', input_per_1m: 0.50, output_per_1m: 3.00 },
      { id: 'gemini-3.1-flash-lite-preview', label: 'Gemini 3.1 Flash-Lite Preview', input_per_1m: 0.25, output_per_1m: 1.50 },
      { id: 'gemini-2.5-flash', label: 'Gemini 2.5 Flash', input_per_1m: 0.30, output_per_1m: 2.50 },
      { id: 'gemini-2.5-flash-lite', label: 'Gemini 2.5 Flash-Lite', input_per_1m: 0.10, output_per_1m: 0.40 },
      { id: 'gemini-2.5-pro', label: 'Gemini 2.5 Pro', input_per_1m: 1.25, output_per_1m: 10.00 }
    ];

    function formatBytes(bytes) {
      if (!bytes) return '0 MB';
      return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
    }

    function escapeHtml(value) {
      return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    async function loadModelOptions() {
      try {
        const res = await fetch('/models');
        const data = await res.json();
        if (!res.ok || !Array.isArray(data.models) || data.models.length === 0) return;
        renderModelOptions(data.models);
      } catch (err) {
        console.warn('Could not load model options:', err);
        renderModelOptions(FALLBACK_MODELS);
      }
    }

    function renderModelOptions(models) {
      const currentValue = modelNameInput.value || 'gemini-3-flash-preview';
      modelNameInput.innerHTML = '';
      models.forEach(model => {
        const option = document.createElement('option');
        option.value = model.id;
        option.textContent = `${model.label} - $${model.input_per_1m}/$${model.output_per_1m} per 1M`;
        modelNameInput.appendChild(option);
      });
      if ([...modelNameInput.options].some(option => option.value === currentValue)) {
        modelNameInput.value = currentValue;
      }
    }

    renderModelOptions(FALLBACK_MODELS);
    loadModelOptions();
    updateProviderState();

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, event => {
        event.preventDefault();
        event.stopPropagation();
      });
    });

    ['dragenter', 'dragover'].forEach(eventName => {
      dropZone.addEventListener(eventName, () => {
        dropZone.classList.add('border-brand-500', 'bg-brand-50');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, () => {
        if (!state.file) dropZone.classList.remove('border-brand-500', 'bg-brand-50');
      });
    });

    dropZone.addEventListener('drop', event => {
      const files = event.dataTransfer.files;
      if (files.length) handleFile(files[0]);
    });

    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        fileInput.click();
      }
    });

    // Cmd/Ctrl+U to open file picker
    document.addEventListener('keydown', e => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'u') {
        e.preventDefault();
        fileInput.click();
      }
    });

    fileInput.addEventListener('change', event => {
      if (event.target.files.length) handleFile(event.target.files[0]);
    });

    referenceProviderInput.addEventListener('change', updateProviderState);

    function updateProviderState() {
      const isFortinet = referenceProviderInput.value === 'fortinet';
      enrichmentRow.classList.toggle('opacity-60', !isFortinet);
      skipEnrichmentInput.disabled = !isFortinet;
      if (!isFortinet) skipEnrichmentInput.checked = true;
    }

    function handleFile(file) {
      const isPdf = file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf');
      if (!isPdf) {
        showStatus('error', 'Invalid file type', 'Upload a PDF file to continue.');
        return;
      }
      revokeLastCompletedDownload();
      state.file = file;
      state.pendingStoredName = null;
      state.pendingOriginalName = null;
      state.pendingModelName = null;
      state.pendingReferenceProvider = null;
      state.lastCompletedDownload = null;
      selectedFileName.textContent = file.name;
      selectedFileSize.textContent = formatBytes(file.size);
      dropZoneContent.classList.add('hidden');
      filePreview.classList.remove('hidden');
      filePreview.classList.add('flex');
      dropZone.classList.add('border-brand-500', 'bg-brand-50');
      clearStatus();
      clearCurrentDownload();
      updateSteps(0);
      if (window.lucide) window.lucide.createIcons();
    }

    removeFile.addEventListener('click', event => {
      event.stopPropagation();
      revokeLastCompletedDownload();
      state.file = null;
      state.pendingStoredName = null;
      state.pendingOriginalName = null;
      state.pendingModelName = null;
      state.pendingReferenceProvider = null;
      fileInput.value = '';
      dropZoneContent.classList.remove('hidden');
      filePreview.classList.add('hidden');
      filePreview.classList.remove('flex');
      dropZone.classList.remove('border-brand-500', 'bg-brand-50');
      clearCurrentDownload();
      clearStatus();
      updateSteps(0);
    });

    submitBtn.addEventListener('click', async () => {
      if (!state.file) {
        showStatus('error', 'No PDF selected', 'Choose an RFP PDF before starting.');
        return;
      }
      if (state.isProcessing) return;

      setProcessing(true, 'Estimating...');
      showStatus('processing', 'Estimating cost', 'The PDF is being checked before processing starts.');
      serverState.textContent = 'Estimating';

      const formData = new FormData();
      formData.append('rfp_file', state.file);
      formData.append('model_name', modelNameInput.value);
      formData.append('start_page', startPageInput.value);
      formData.append('end_page', endPageInput.value);

      try {
        const res = await fetch('/estimate_cost', { method: 'POST', body: formData });
        const data = await parseJsonResponse(res);
        if (!res.ok) throw new Error(data.error || 'Cost estimation failed.');

        state.pendingStoredName = data.stored_name;
        state.pendingOriginalName = data.original_name;
        state.pendingModelName = data.model_name;
        state.pendingReferenceProvider = referenceProviderInput.value;

        const cost = data.cost;
        document.getElementById('cModel').textContent = cost.model_label || cost.model;
        document.getElementById('cPages').textContent = cost.num_pages.toLocaleString();
        document.getElementById('cChunks').textContent = cost.num_chunks.toLocaleString();
        document.getElementById('cInputRate').textContent = `$${cost.input_price_per_1m.toFixed(2)}`;
        document.getElementById('cOutputRate').textContent = `$${cost.output_price_per_1m.toFixed(2)}`;
        document.getElementById('cInputTok').textContent = cost.estimated_input_tokens.toLocaleString();
        document.getElementById('cOutputTok').textContent = cost.estimated_output_tokens.toLocaleString();
        document.getElementById('cInputCost').textContent = `$${cost.input_cost_usd.toFixed(6)}`;
        document.getElementById('cOutputCost').textContent = `$${cost.output_cost_usd.toFixed(6)}`;
        document.getElementById('cTotal').textContent = `$${cost.total_cost_usd.toFixed(6)}`;

        setProcessing(false);
        serverState.textContent = 'Ready';
        costModal.classList.remove('hidden');
        costModal.classList.add('flex');
        if (window.lucide) window.lucide.createIcons();
      } catch (err) {
        showStatus('error', 'Estimation failed', err.message);
        setProcessing(false);
        serverState.textContent = 'Ready';
      }
    });

    costCancelBtn.addEventListener('click', () => {
      costModal.classList.add('hidden');
      costModal.classList.remove('flex');
      state.pendingStoredName = null;
      state.pendingModelName = null;
      state.pendingReferenceProvider = null;
      clearStatus();
    });

    costModal.addEventListener('click', event => {
      if (event.target === costModal) costCancelBtn.click();
    });

    costConfirmBtn.addEventListener('click', async () => {
      costModal.classList.add('hidden');
      costModal.classList.remove('flex');
      if (!state.pendingStoredName) return;

      setProcessing(true, 'Processing...');
      serverState.textContent = 'Processing';
      showStatus('processing', 'Processing RFP', 'The run has started. If the tunnel times out, use Refresh to fetch the completed workbook.');
      updateSteps(1);
      clearCurrentDownload('Processing this upload. Refresh will show only this run when it is ready.');

      const formData = new FormData();
      formData.append('stored_name', state.pendingStoredName);
      formData.append('original_name', state.pendingOriginalName);
      formData.append('model_name', state.pendingModelName || modelNameInput.value);
      formData.append('reference_provider', state.pendingReferenceProvider || referenceProviderInput.value);
      formData.append('start_page', startPageInput.value);
      formData.append('end_page', endPageInput.value);
      if (skipEnrichmentInput.checked) formData.append('skip_enrichment', 'on');

      const timers = [
        setTimeout(() => updateSteps(2), 4500),
        setTimeout(() => updateSteps(3), 14000)
      ];

      try {
        const response = await fetch('/process', { method: 'POST', body: formData });
        if (!response.ok) {
          const handled = await handleProcessError(response);
          if (handled) return;
          throw new Error('Pipeline processing failed.');
        }

        updateSteps(4);
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const filename = filenameFromResponse(response) || 'enriched_requirements.xlsx';
        triggerDownload(url, filename);

        revokeLastCompletedDownload();
        state.lastCompletedDownload = {
          name: filename,
          path: null,
          mtime: Date.now() / 1000,
          size: blob.size,
          blobUrl: url
        };
        renderDownloads([state.lastCompletedDownload]);
        showStatus('success', 'Workbook ready', 'The generated Excel file has been downloaded and is listed in Current Result.');
        setProcessing(false);
        serverState.textContent = 'Ready';
      } catch (error) {
        console.error(error);
        showStatus('error', 'Processing failed', error.message);
        setProcessing(false);
        serverState.textContent = 'Ready';
        updateSteps(0);
      } finally {
        timers.forEach(clearTimeout);
      }
    });

    async function parseJsonResponse(response) {
      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) return response.json();
      const text = await response.text();
      return { error: text || `HTTP ${response.status}` };
    }

    async function handleProcessError(response) {
      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Pipeline processing failed.');
      }
      if (response.status === 504 || response.status === 503) {
        showStatus('processing', 'Processing in background', 'The tunnel stopped waiting, but the backend may still finish the file. Click Refresh in Current Result after a minute.');
        updateSteps(3);
        setProcessing(false);
        serverState.textContent = 'Background run';
        return true;
      }
      if (response.status === 502) {
        throw new Error('Server returned 502. Check backend logs and try again with enrichment disabled if memory is tight.');
      }
      if (response.status === 413) {
        throw new Error('The PDF is too large for the current server upload limit.');
      }
      throw new Error(`Server error ${response.status}.`);
    }

    function filenameFromResponse(response) {
      const header = response.headers.get('Content-Disposition') || '';
      const utfMatch = header.match(/filename\*=UTF-8''([^;]+)/i);
      if (utfMatch) return decodeURIComponent(utfMatch[1]);
      const quoted = header.match(/filename="?([^"]+)"?/i);
      return quoted ? quoted[1] : '';
    }

    function triggerDownload(url, filename) {
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }

    function setProcessing(isProcessing, label) {
      state.isProcessing = isProcessing;
      submitBtn.disabled = isProcessing;
      btnSpinner.classList.toggle('hidden', !isProcessing);
      btnIcon.classList.toggle('hidden', isProcessing);
      btnText.textContent = label || 'Estimate & Process';
    }

    function showStatus(type, title, desc) {
      const styles = {
        processing: 'border-amber-200 bg-amber-50 text-amber-900',
        success:    'border-brand-200 bg-brand-50 text-brand-700',
        error:      'border-red-200 bg-red-50 text-red-900'
      };
      statusArea.className = `mt-5 rounded-xl border p-4 fade-in ${styles[type] || styles.processing}`;
      statusTitle.textContent = title;
      statusDesc.textContent = desc;
      statusDesc.className = 'mt-1 text-[13px] leading-5 opacity-80';
    }

    function clearStatus() {
      statusArea.className = 'mt-5 hidden rounded-xl border p-4';
      statusTitle.textContent = '';
      statusDesc.textContent = '';
    }

    function updateSteps(step) {
      for (let i = 1; i <= 4; i++) {
        const el = document.getElementById(`step${i}`);
        const num = el.querySelector('.step-num');
        const active = i <= step;
        const current = i === step;
        num.className = active
          ? `step-num relative z-10 grid h-8 w-8 place-items-center rounded-full bg-brand-grad text-[11px] font-bold text-white ring-4 ring-white shadow-soft ${current ? 'animate-pulse' : ''}`
          : 'step-num relative z-10 grid h-8 w-8 place-items-center rounded-full bg-steel-100 text-[11px] font-bold text-steel-500 ring-4 ring-white';
        if (active && !current) num.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
        else num.textContent = String(i);
      }
    }

    function clearCurrentDownload(message = 'No workbook has been generated for this upload yet.') {
      downloadsList.innerHTML = `<div class="rounded-xl border border-dashed border-line bg-steel-50/60 px-4 py-6 text-center text-[12.5px] leading-5 text-steel-500">${escapeHtml(message)}</div>`;
    }

    function encodeDownloadPath(path) {
      return String(path || '').split('/').map(encodeURIComponent).join('/');
    }

    function revokeLastCompletedDownload() {
      if (state.lastCompletedDownload && state.lastCompletedDownload.blobUrl) {
        window.URL.revokeObjectURL(state.lastCompletedDownload.blobUrl);
      }
      state.lastCompletedDownload = null;
    }

    function renderDownloads(files) {
      downloadsList.innerHTML = '';
      if (!files || files.length === 0) {
        clearCurrentDownload('This run is still processing. Refresh again in a minute.');
        return;
      }
      const file = files[0];
      const date = new Date(file.mtime * 1000).toLocaleString();
      const size = formatBytes(file.size);
      const href = file.blobUrl || `/download/${encodeDownloadPath(file.path)}`;
      const item = document.createElement('div');
      item.className = 'fade-in flex flex-col gap-3 rounded-xl border border-line bg-gradient-to-br from-white to-steel-50/50 p-3.5 shadow-soft sm:flex-row sm:items-center sm:justify-between';
      item.innerHTML = `
        <div class="flex min-w-0 items-center gap-3">
          <div class="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-brand-grad text-white">
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
          </div>
          <div class="min-w-0">
            <div class="truncate text-[13px] font-semibold tracking-tight">${escapeHtml(file.name)}</div>
            <div class="mt-0.5 text-[11.5px] text-steel-500 font-mono">${escapeHtml(date)} - ${escapeHtml(size)}</div>
          </div>
        </div>
        <a class="inline-flex h-9 items-center justify-center gap-1.5 rounded-lg bg-ink px-3 text-[12.5px] font-semibold text-white transition hover:bg-steel-700" href="${href}" download="${escapeHtml(file.name)}">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          <span>Download</span>
        </a>
      `;
      downloadsList.appendChild(item);
    }

    async function fetchRecentDownloads() {
      if (!state.pendingStoredName) {
        clearCurrentDownload();
        return;
      }
      try {
        refreshDownloadsBtn.disabled = true;
        refreshDownloadsBtn.querySelector('span').textContent = 'Checking...';
        const res = await fetch(`/recent_downloads?stored_name=${encodeURIComponent(state.pendingStoredName)}`);
        const data = await res.json();
        renderDownloads(data.files || []);
      } catch (err) {
        console.error('Failed to fetch downloads:', err);
        clearCurrentDownload('Could not check this run yet. Try Refresh again.');
      } finally {
        refreshDownloadsBtn.disabled = false;
        refreshDownloadsBtn.querySelector('span').textContent = 'Refresh';
      }
    }

    refreshDownloadsBtn.addEventListener('click', fetchRecentDownloads);
});

