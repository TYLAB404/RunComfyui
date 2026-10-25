const { createApp, ref, computed, onMounted, onUnmounted } = Vue;

createApp({
  setup() {
    // 基础请求包装器（自动附加 JWT Bearer Header）
    const authFetch = (url, options = {}) => {
      const token = localStorage.getItem('rh_auth_token');
      const headers = options.headers ? { ...options.headers } : {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      return fetch(url, { ...options, headers });
    };

    // ================= 用户鉴权与 Turnstile 状态 =================
    const currentUser = ref(null);
        const isBroadcastDismissed = ref(false);
    if (sessionStorage.getItem('rh_broadcast_dismissed') === 'true') {
      isBroadcastDismissed.value = true;
    }
    const dismissBroadcast = () => {
      isBroadcastDismissed.value = true;
      sessionStorage.setItem('rh_broadcast_dismissed', 'true');
    };

    const publicConfig = ref({
      siteTitle: 'RunningHub 智能创作平台',
      turnstileEnabled: false,
      turnstileSiteKey: '',
      allowRegistration: true,
      requireLoginToGenerate: false,
      isFirstUser: false
    });
    const showAuthModal = ref(false);
    const authTab = ref('signin'); // 'signin' | 'signup'
    const authForm = ref({
      identifier: '',
      username: '',
      email: '',
      password: '',
      confirmPassword: '',
      turnstileToken: ''
    });
    const authLoading = ref(false);
    const authError = ref('');
    const authSuccessMsg = ref('');
    const showUserDropdown = ref(false);
    const turnstileWidgetId = ref(null);

    // 修改密码弹窗状态
    const showChangePwdModal = ref(false);
    const pwdForm = ref({ oldPassword: '', newPassword: '', confirmPassword: '' });
    const pwdLoading = ref(false);
    const pwdError = ref('');
    const pwdSuccessMsg = ref('');

    // ================= 开发者后台管理 (Admin) 状态 =================
    const adminTab = ref('overview'); // 'overview' | 'users' | 'system' | 'tasks'
    const adminOverview = ref({});
    const adminUsers = ref([]);
    const adminTasks = ref([]);
    const adminSystem = ref({
      siteTitle: 'RunningHub 智能调度中心',
      turnstileEnabled: false,
      turnstileSiteKey: '',
      turnstileSecretKey: '',
      turnstileSecretKeyMasked: '',
      hasTurnstileSecret: false,
      allowRegistration: true,
      defaultUserPoints: 100,
      requireLoginToGenerate: false
    });
    const adminLoading = ref(false);
    const adminSearchUser = ref('');
    const editingUser = ref(null);
    const editUserForm = ref({ role: 'user', points: 100, isActive: true, newPassword: '' });

    const activeTab = ref('workflows');
    const config = ref({ hasKey: false, activeKeyId: '', activeKeyName: '', activeMaskedKey: '', workflows: [] });
    const keys = ref([]);
    const activeKeyId = ref('');
    const activeKeyName = ref('');
    const activeMaskedKey = ref('');
    const showKeyDropdown = ref(false);
    const showKeyPlainText = ref(false);
    const isAddingKey = ref(false);
    const testingKeyId = ref(null);
    const keyTestResult = ref({});
    const newKeyForm = ref({ name: '', apiKey: '', note: '', setActive: true });
    const selectedTaskType = ref('Standard'); // 'Standard' (极速推荐) 或 'Lite' (经济排队)

    const workflows = ref([]);
    const selectedWorkflowId = ref('');

    // 工作流市场/创作中心 过滤与分类状态
    const workflowSearch = ref('');
    const selectedWfCategory = ref('全部');
    const workflowCategories = ref(['全部', '视频生成', '图像精绘', '声音音频', '画质增强']);

    const filteredWorkflows = computed(() => {
      let list = workflows.value || [];
      if (selectedWfCategory.value !== '全部') {
        list = list.filter(w => (w.category || '视频生成') === selectedWfCategory.value);
      }
      if (workflowSearch.value && workflowSearch.value.trim()) {
        const q = workflowSearch.value.trim().toLowerCase();
        list = list.filter(w => 
          (w.name && w.name.toLowerCase().includes(q)) ||
          (w.id && String(w.id).toLowerCase().includes(q)) ||
          (w.description && w.description.toLowerCase().includes(q)) ||
          (w.ownerName && w.ownerName.toLowerCase().includes(q))
        );
      }
      return list;
    });

    const officialWorkflows = computed(() => {
      return filteredWorkflows.value.filter(w => Boolean(w.isOfficial));
    });

    const userWorkflows = computed(() => {
      return filteredWorkflows.value.filter(w => !Boolean(w.isOfficial));
    });
    const tasks = ref([]);
    const gallery = ref([]);
    const isGenerating = ref(false);
    const isDetecting = ref(false);
    const isLoadingSchema = ref(false);
    const lightboxUrl = ref(null);
    const showAddWorkflowModal = ref(false);
    const activeOutputIndex = ref(0);

    // 动态解析得到的 Schema 与绑定的响应式参数
    const dynamicSchema = ref(null);
    const dynamicSchemaTotalNodes = ref(0);
    const dynamicPrompts = ref([]);
    const dynamicSampler = ref(null);
    const dynamicLatent = ref(null);
    const dynamicImages = ref([]);
    const dynamicVideos = ref([]);
    const dynamicAudios = ref([]);
    const dynamicQuality = ref([]);
    const allEditableNodes = ref([]);

    // 本地上传的 ComfyUI 工作流 (免 workflowId 原生代理执行模式)
    const customWorkflow = ref(null);
    const workflowFileInput = ref(null);

    // 全节点覆盖字典与原始默认字典（严格只提交用户修改过的字段）
    const nodeOverrides = ref({});
    const originalDefaults = ref({});
    const showAllNodes = ref(false);
    const allNodesSearch = ref('');

    // 现代化交互通知系统 (Toast)
    const toastState = ref({
      show: false,
      message: '',
      type: 'info' // success, error, warning, info
    });
    let toastTimer = null;

    const showToastNotification = (msg, type = 'info') => {
      if (toastTimer) clearTimeout(toastTimer);
      toastState.value = {
        show: true,
        message: String(msg),
        type: type
      };
      toastTimer = setTimeout(() => {
        toastState.value.show = false;
      }, 4000);
    };

    // 现代化自定义操作确认弹窗 (彻底替换原生黑框 confirm)
    const confirmModal = ref({
      show: false,
      title: '操作确认',
      message: '',
      confirmText: '确定',
      cancelText: '取消',
      type: 'danger',
      onConfirm: () => {},
      onCancel: () => {}
    });

    const confirmAction = ({ title, message, confirmText = '确定', cancelText = '取消', type = 'danger' }) => {
      return new Promise((resolve) => {
        confirmModal.value = {
          show: true,
          title: title || '操作确认',
          message: message || '确定要执行此操作吗？',
          confirmText,
          cancelText,
          type,
          onConfirm: () => {
            confirmModal.value.show = false;
            resolve(true);
          },
          onCancel: () => {
            confirmModal.value.show = false;
            resolve(false);
          }
        };
      });
    };

    // 全局防穿透重写 window.alert，杜绝浏览器任何原生黑框
    window.alert = (msg) => {
      showToastNotification(msg, 'info');
    };

    const newWf = ref({
      id: '',
      name: '',
      category: '视频生成',
      description: ''
    });

    let pollingTimer = null;

    // 当前选中的工作流元数据
    const currentWorkflow = computed(() => {
      return workflows.value.find(w => w.id === selectedWorkflowId.value);
    });

    // 正在运行中的任务数量
    const runningTasksCount = computed(() => {
      return tasks.value.filter(t => t.status === 'RUNNING' || t.status === 'QUEUED').length;
    });

    // 最近的一个任务
    const latestTask = computed(() => {
      return tasks.value.length > 0 ? tasks.value[0] : null;
    });

    // 当前在监视面板中展示的输出媒体
    const currentDisplayOutput = computed(() => {
      if (!latestTask.value || !latestTask.value.outputs || latestTask.value.outputs.length === 0) {
        return null;
      }
      const idx = activeOutputIndex.value;
      if (idx >= 0 && idx < latestTask.value.outputs.length) {
        return latestTask.value.outputs[idx];
      }
      return latestTask.value.outputs[0];
    });

    // 判断是否为视频文件/URL
    const isVideoUrl = (url) => {
      if (!url) return false;
      const clean = String(url).split('?')[0].toLowerCase();
      return ['.mp4', '.webm', '.mov', '.gif'].some(ext => clean.endsWith(ext));
    };

    // 判断当前输出对象是否为视频
    const isVideoOutput = (out) => {
      if (!out) return false;
      if (out.fileType === 'video' || out.fileType === 'mp4' || out.fileType === 'webm') return true;
      return isVideoUrl(out.url) || isVideoUrl(out.filename);
    };

    // 判断是否为音频文件/URL
    const isAudioUrl = (url) => {
      if (!url) return false;
      const clean = String(url).split('?')[0].toLowerCase();
      return ['.mp3', '.wav', '.flac', '.ogg', '.m4a', '.aac', '.wma', '.opus'].some(ext => clean.endsWith(ext));
    };

    // 判断当前输出对象是否为音频
    const isAudioOutput = (out) => {
      if (!out) return false;
      if (out.fileType === 'audio' || out.fileType === 'mp3' || out.fileType === 'wav') return true;
      return isAudioUrl(out.url) || isAudioUrl(out.filename);
    };

    // 统计用户修改过的参数总数
    const modifiedParamsCount = computed(() => {
      let count = 0;
      for (const nid in nodeOverrides.value) {
        for (const fname in nodeOverrides.value[nid]) {
          const cur = nodeOverrides.value[nid][fname];
          const def = originalDefaults.value[nid]?.[fname];
          if (String(cur) !== String(def)) {
            count++;
          }
        }
      }
      return count;
    });

    // 判断具体某个字段是否被修改过
    const isFieldModified = (nodeId, fieldName) => {
      const cur = nodeOverrides.value[nodeId]?.[fieldName];
      const def = originalDefaults.value[nodeId]?.[fieldName];
      return cur !== undefined && def !== undefined && String(cur) !== String(def);
    };

    // 恢复单个字段为原始默认值
    const resetField = (nodeId, fieldName) => {
      if (originalDefaults.value[nodeId] && originalDefaults.value[nodeId][fieldName] !== undefined) {
        nodeOverrides.value[nodeId][fieldName] = originalDefaults.value[nodeId][fieldName];
      }
    };

    // 恢复整个节点为原始默认值
    const resetNode = (nodeId) => {
      if (originalDefaults.value[nodeId]) {
        nodeOverrides.value[nodeId] = { ...originalDefaults.value[nodeId] };
      }
    };

    // 智能诊断当前工作流是否存在云端缺陷（如音频崩端或未开启保存视频）
    const workflowIssues = computed(() => {
      const issues = [];
      if (nodeOverrides.value['137'] && Number(nodeOverrides.value['137'].duration) === 0) {
        issues.push({
          id: 'audio_duration',
          title: 'Node #137 (EmptyAudio) duration 为 0',
          desc: '会导致后方 Node #138 在云端 PyAV 编码时报 [Errno 12] Cannot allocate memory 崩溃，建议修正为 1 秒。'
        });
      }
      if (nodeOverrides.value['141'] && nodeOverrides.value['141'].save_output === false) {
        issues.push({
          id: 'video_save_output',
          title: 'Node #141 (VHS_VideoCombine) save_output 为 false',
          desc: '默认未开启最终成果保存，会导致云端 OpenAPI 无法提供最终 MP4 视频下载，建议开启。'
        });
      }
      return issues;
    });

    // 一键应用推荐修复
    const applyRecommendedFixes = () => {
      if (nodeOverrides.value['137'] && originalDefaults.value['137']?.duration !== undefined) {
        nodeOverrides.value['137']['duration'] = 1;
      }
      if (nodeOverrides.value['141'] && originalDefaults.value['141']?.save_output !== undefined) {
        nodeOverrides.value['141']['save_output'] = true;
      }
    };

    // 过滤后的全量节点列表
    const filteredAllNodes = computed(() => {
      const q = allNodesSearch.value.trim().toLowerCase();
      if (!q) return allEditableNodes.value;
      return allEditableNodes.value.filter(n => {
        const matchId = String(n.nodeId).includes(q);
        const matchType = String(n.class_type).toLowerCase().includes(q);
        const matchField = Object.keys(n.fields || {}).some(k => k.toLowerCase().includes(q));
        return matchId || matchType || matchField;
      });
    });

    // 获取配置与工作流列表
    const fetchConfig = async () => {
      try {
        const res = await authFetch('/api/config');
        const data = await res.json();
        config.value = data;
        workflows.value = data.workflows || [];
        keys.value = data.keys || [];
        activeKeyId.value = data.activeKeyId || '';
        activeKeyName.value = data.activeKeyName || '';
        activeMaskedKey.value = data.activeMaskedKey || '';

        if (workflows.value.length > 0 && selectedWorkflowId.value) {
          await loadWorkflowSchema(selectedWorkflowId.value);
        }
      } catch (err) {
        console.error('Failed to load config:', err);
      }
    };

    // 统一将解析好的 ComfyUI dynamicSchema 绑定到响应式表单中
    const applyParsedSchema = (data) => {
      dynamicSchema.value = data.dynamicSchema;
      dynamicSchemaTotalNodes.value = data.totalNodes;

      // 初始化全量字段字典
      const overrides = {};
      const defaults = {};
      (data.dynamicSchema.allEditableNodes || []).forEach(node => {
        overrides[node.nodeId] = { ...node.fields };
        defaults[node.nodeId] = { ...node.fields };
      });
      nodeOverrides.value = overrides;
      originalDefaults.value = defaults;
      allEditableNodes.value = data.dynamicSchema.allEditableNodes || [];

      // 1. 动态生成提示词绑定表单
      dynamicPrompts.value = (data.dynamicSchema.promptNodes || []).map(p => ({
        nodeId: p.nodeId,
        role: p.role,
        label: p.label,
        fieldName: p.fieldName || 'text',
        currentValue: p.defaultValue || ''
      }));

      // 2. 动态采样器/步数调度绑定 (严格只包含该节点实际存在的字段)
      if (data.dynamicSchema.samplerNode) {
        const sn = data.dynamicSchema.samplerNode;
        dynamicSampler.value = {
          nodeId: sn.nodeId,
          class_type: sn.class_type,
          fields: { ...sn.fields }
        };
      } else {
        dynamicSampler.value = null;
      }

      // 3. 动态尺寸绑定 (EmptyLatentImage)
      if (data.dynamicSchema.latentNode) {
        const ln = data.dynamicSchema.latentNode;
        dynamicLatent.value = {
          nodeId: ln.nodeId,
          class_type: ln.class_type,
          fields: {
            width: ln.fields.width || 512,
            height: ln.fields.height || 512,
            batch_size: ln.fields.batch_size || 1
          }
        };
      } else {
        dynamicLatent.value = null;
      }

      // 4. 动态参考图输入 (LoadImage)
      dynamicImages.value = (data.dynamicSchema.imageNodes || []).map(im => ({
        nodeId: im.nodeId,
        fieldName: im.fieldName || 'image',
        defaultValue: im.defaultValue || '',
        uploadedFileName: '',
        previewUrl: null,
        isUploading: false
      }));

      // 5. 动态参考视频输入 (VHS_LoadVideo)
      dynamicVideos.value = (data.dynamicSchema.videoNodes || []).map(vm => ({
        nodeId: vm.nodeId,
        fieldName: vm.fieldName || 'video',
        defaultValue: vm.defaultValue || '',
        uploadedFileName: '',
        previewUrl: null,
        isUploading: false
      }));

      // 5.1 动态参考音频输入 (LoadAudio / VHS_LoadAudio 等)
      dynamicAudios.value = (data.dynamicSchema.audioNodes || []).map(am => ({
        nodeId: am.nodeId,
        fieldName: am.fieldName || 'audio',
        defaultValue: am.defaultValue || '',
        uploadedFileName: '',
        previewUrl: null,
        isUploading: false
      }));

      // 6. 动态画质基准参数 (PrimitiveInt 等)
      dynamicQuality.value = (data.dynamicSchema.qualityNodes || []).map(qm => ({
        nodeId: qm.nodeId,
        fieldName: qm.fieldName || 'value',
        defaultValue: qm.defaultValue,
        currentValue: qm.defaultValue
      }));
    };

    // 动态拉取指定工作流在云端的真实节点拓扑
    const loadWorkflowSchema = async (wfId) => {
      if (!wfId || wfId === 'custom_upload') return;
      isLoadingSchema.value = true;
      try {
        const res = await authFetch('/api/workflows/inspect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ workflowId: wfId })
        });
        const data = await res.json();
        if (data.status === 'ok') {
          applyParsedSchema(data);
        } else {
          console.warn('获取工作流节点结构失败:', data);
        }
      } catch (err) {
        console.error('拉取工作流节点失败:', err);
      } finally {
        isLoadingSchema.value = false;
      }
    };

    // 触发导入本地 ComfyUI 工作流 JSON 文件
    const triggerUploadWorkflowFile = () => {
      if (workflowFileInput.value) {
        workflowFileInput.value.click();
      }
    };

    // 清除自定义工作流并切回预设工作流
    const clearCustomWorkflow = () => {
      customWorkflow.value = null;
      if (workflows.value.length > 0) {
        selectedWorkflowId.value = workflows.value[0].id;
        loadWorkflowSchema(selectedWorkflowId.value);
      }
    };

    // 处理用户选择的本地工作流 JSON 文件
    const handleWorkflowFileSelected = async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;

      const formData = new FormData();
      formData.append('file', file);

      isLoadingSchema.value = true;
      try {
        const res = await authFetch('/api/workflows/parse_json', {
          method: 'POST',
          body: formData
        });
        const data = await res.json();
        if (data.status === 'ok') {
          customWorkflow.value = {
            name: data.workflowName,
            totalNodes: data.totalNodes,
            prompt: data.customPrompt
          };
          selectedWorkflowId.value = 'custom_upload';
          applyParsedSchema(data);
          activeTab.value = 'studio';
          showToastNotification(`成功解析本地工作流【${data.workflowName}】（共 ${data.totalNodes} 个节点）`, 'success');
          window.scrollTo({ top: 0, behavior: 'smooth' });
        } else {
          showToastNotification('解析本地工作流失败: ' + (data.detail || JSON.stringify(data)), 'error');
        }
      } catch (err) {
        showToastNotification('上传工作流文件发生异常: ' + err.message, 'error');
      } finally {
        isLoadingSchema.value = false;
        if (e.target) e.target.value = '';
      }
    };

    // 切换工作流时重新动态解析
    const onWorkflowChange = async () => {
      await loadWorkflowSchema(selectedWorkflowId.value);
    };

    // 获取任务列表 (带增量指纹比对，避免无变动时频繁引起 Vue 虚拟 DOM 遍历与内存抖动)
    let lastTasksHash = '';
    const refreshTasks = async () => {
      try {
        const res = await authFetch('/api/tasks');
        const data = await res.json();
        if (Array.isArray(data)) {
          const newHash = data.map(t => `${t.taskId}:${t.status}:${(t.outputs||[]).length}`).join('|');
          if (newHash !== lastTasksHash) {
            lastTasksHash = newHash;
            tasks.value = data;
          }

          const hasActive = data.some(t => t.status === 'RUNNING' || t.status === 'QUEUED');
          if (!hasActive) {
            isGenerating.value = false;
          }
        }
      } catch (err) {
        console.error('Failed to fetch tasks:', err);
      }
    };

    // 获取本地画廊 (带指纹比对，仅在有新产出或增删时触发重绘)
    let lastGalleryHash = '';
    const refreshGallery = async () => {
      try {
        const res = await authFetch('/api/gallery');
        const data = await res.json();
        if (Array.isArray(data)) {
          const newHash = data.map(g => `${g.filename}:${g.fileType}`).join('|');
          if (newHash !== lastGalleryHash) {
            lastGalleryHash = newHash;
            gallery.value = data;
          }
          nextTick(() => { if (window.lucide) window.lucide.createIcons(); });
        }
      } catch (err) {
        console.error('Failed to fetch gallery:', err);
      }
    };

    // 随机种子
    const randomizeDynamicSeed = () => {
      if (dynamicSampler.value && dynamicSampler.value.fields) {
        dynamicSampler.value.fields.seed = Math.floor(Math.random() * 9999999999);
      }
    };

    // 参考图上传处理 (自动上传至 RunningHub OpenAPI 并关联对应节点)
    const handleNodeImageUpload = async (event, imgNode) => {
      const file = event.target.files[0];
      if (!file) return;

      imgNode.previewUrl = URL.createObjectURL(file);
      imgNode.isUploading = true;

      const formData = new FormData();
      formData.append('file', file);

      try {
        const res = await authFetch('/api/upload', {
          method: 'POST',
          body: formData
        });
        const data = await res.json();
        if (data.status === 'ok') {
          imgNode.uploadedFileName = data.fileName;
          // 同步写入全节点覆盖字典
          if (!nodeOverrides.value[imgNode.nodeId]) {
            nodeOverrides.value[imgNode.nodeId] = {};
          }
          nodeOverrides.value[imgNode.nodeId][imgNode.fieldName] = data.fileName;
        } else {
          showToastNotification('图片上传失败: ' + (data.detail || '未知原因'), 'error');
          imgNode.previewUrl = null;
          imgNode.uploadedFileName = '';
        }
      } catch (err) {
        showToastNotification('图片上传发生异常: ' + err.message, 'error');
        imgNode.previewUrl = null;
        imgNode.uploadedFileName = '';
      } finally {
        imgNode.isUploading = false;
      }
    };

    // 参考视频上传处理 (自动上传至 RunningHub OpenAPI 并关联对应节点)
    const handleNodeVideoUpload = async (event, vidNode) => {
      const file = event.target.files[0];
      if (!file) return;

      vidNode.previewUrl = URL.createObjectURL(file);
      vidNode.isUploading = true;

      const formData = new FormData();
      formData.append('file', file);

      try {
        const res = await authFetch('/api/upload', {
          method: 'POST',
          body: formData
        });
        const data = await res.json();
        if (data.status === 'ok') {
          vidNode.uploadedFileName = data.fileName;
          // 同步写入全节点覆盖字典
          if (!nodeOverrides.value[vidNode.nodeId]) {
            nodeOverrides.value[vidNode.nodeId] = {};
          }
          nodeOverrides.value[vidNode.nodeId][vidNode.fieldName] = data.fileName;
        } else {
          showToastNotification('视频上传失败: ' + (data.detail || '未知原因'), 'error');
          vidNode.previewUrl = null;
          vidNode.uploadedFileName = '';
        }
      } catch (err) {
        showToastNotification('视频上传发生异常: ' + err.message, 'error');
        vidNode.previewUrl = null;
        vidNode.uploadedFileName = '';
      } finally {
        vidNode.isUploading = false;
      }
    };

    // 参考音频上传处理 (自动上传至 RunningHub OpenAPI 并关联对应节点)
    const handleNodeAudioUpload = async (event, audNode) => {
      const file = event.target.files[0];
      if (!file) return;

      audNode.previewUrl = URL.createObjectURL(file);
      audNode.isUploading = true;

      const formData = new FormData();
      formData.append('file', file);

      try {
        const res = await authFetch('/api/upload', {
          method: 'POST',
          body: formData
        });
        const data = await res.json();
        if (data.status === 'ok') {
          audNode.uploadedFileName = data.fileName;
          // 同步写入全节点覆盖字典
          if (!nodeOverrides.value[audNode.nodeId]) {
            nodeOverrides.value[audNode.nodeId] = {};
          }
          nodeOverrides.value[audNode.nodeId][audNode.fieldName] = data.fileName;
        } else {
          showToastNotification('音频上传失败: ' + (data.detail || '未知原因'), 'error');
          audNode.previewUrl = null;
          audNode.uploadedFileName = '';
        }
      } catch (err) {
        showToastNotification('音频上传发生异常: ' + err.message, 'error');
        audNode.previewUrl = null;
        audNode.uploadedFileName = '';
      } finally {
        audNode.isUploading = false;
      }
    };

    // 提交运行生成任务：严格遵循“未修改不注入”铁律，只提交用户确实更改过的参数！
    const submitDynamicGeneration = async () => {
      if (!config.value.hasKey) {
        showToastNotification('当前平台算力引擎未就绪（未配置有效 API Key），请联系系统管理员配置启用', 'warning');
        return;
      }

      if (!selectedWorkflowId.value) {
        showToastNotification('请先选择一个工作流', 'warning');
        return;
      }

      isGenerating.value = true;

      // 1. 同步上层快捷组件中的修改到 nodeOverrides
      // 提示词
      dynamicPrompts.value.forEach(p => {
        if (!nodeOverrides.value[p.nodeId]) nodeOverrides.value[p.nodeId] = {};
        if (p.currentValue !== undefined && p.currentValue !== null) {
          nodeOverrides.value[p.nodeId][p.fieldName] = p.currentValue;
        }
      });

      // 采样器与步数同步 (严格检查字段是否存在)
      if (dynamicSampler.value) {
        const snId = String(dynamicSampler.value.nodeId);
        if (nodeOverrides.value[snId]) {
          const f = dynamicSampler.value.fields;
          for (const k in f) {
            if (originalDefaults.value[snId] && originalDefaults.value[snId][k] !== undefined) {
              const val = f[k];
              nodeOverrides.value[snId][k] = typeof originalDefaults.value[snId][k] === 'number' ? Number(val) : val;
            }
          }
        }
      }

      // 尺寸
      if (dynamicLatent.value) {
        const lnId = String(dynamicLatent.value.nodeId);
        if (nodeOverrides.value[lnId]) {
          const f = dynamicLatent.value.fields;
          if (f.width !== undefined && originalDefaults.value[lnId]?.width !== undefined) nodeOverrides.value[lnId]['width'] = Number(f.width);
          if (f.height !== undefined && originalDefaults.value[lnId]?.height !== undefined) nodeOverrides.value[lnId]['height'] = Number(f.height);
        }
      }

      // 画质/分辨率
      dynamicQuality.value.forEach(q => {
        const qId = String(q.nodeId);
        if (nodeOverrides.value[qId] && originalDefaults.value[qId]?.[q.fieldName] !== undefined) {
          nodeOverrides.value[qId][q.fieldName] = Number(q.currentValue);
        }
      });

      // 参考图
      dynamicImages.value.forEach(im => {
        if (im.uploadedFileName) {
          const imId = String(im.nodeId);
          if (nodeOverrides.value[imId] && originalDefaults.value[imId]?.[im.fieldName] !== undefined) {
            nodeOverrides.value[imId][im.fieldName] = im.uploadedFileName;
          }
        }
      });

      // 参考视频
      dynamicVideos.value.forEach(vm => {
        if (vm.uploadedFileName) {
          const vmId = String(vm.nodeId);
          if (nodeOverrides.value[vmId] && originalDefaults.value[vmId]?.[vm.fieldName] !== undefined) {
            nodeOverrides.value[vmId][vm.fieldName] = vm.uploadedFileName;
          }
        }
      });

      // 参考音频
      dynamicAudios.value.forEach(am => {
        if (am.uploadedFileName) {
          const amId = String(am.nodeId);
          if (nodeOverrides.value[amId] && originalDefaults.value[amId]?.[am.fieldName] !== undefined) {
            nodeOverrides.value[amId][am.fieldName] = am.uploadedFileName;
          }
        }
      });

      // 2. 严格比对：仅将确实与原始默认不同的字段加入 nodeInfoList
      const nodeInfoList = [];
      const submittedKeys = new Set();

      for (const nid in nodeOverrides.value) {
        const fields = nodeOverrides.value[nid];
        const defaults = originalDefaults.value[nid] || {};
        for (const fname in fields) {
          // 门禁 1：如果该字段在云端节点的原始 inputs 中根本不存在，绝对禁止提交！
          if (defaults[fname] === undefined) {
            continue;
          }

          const curVal = fields[fname];
          const defVal = defaults[fname];
          const key = `${nid}_${fname}`;

          // 门禁 2：只有与默认值不同（或被显式修改）才提交
          if (String(curVal) !== String(defVal) && !submittedKeys.has(key)) {
            submittedKeys.add(key);
            let finalVal = curVal;
            // 保持数值类型的纯净
            if (typeof defVal === 'number') {
              finalVal = Number(curVal);
            } else if (typeof defVal === 'boolean') {
              finalVal = Boolean(curVal);
            }
            nodeInfoList.push({
              nodeId: String(nid),
              fieldName: fname,
              fieldValue: finalVal
            });
          }
        }
      }

      // 提取核心正向提示词用于任务展示记录
      const mainPrompt = dynamicPrompts.value.length > 0 ? dynamicPrompts.value[0].currentValue : '';
      const isCustom = selectedWorkflowId.value === 'custom_upload' && customWorkflow.value;

      const payload = {
        workflowId: selectedWorkflowId.value,
        workflowName: isCustom ? customWorkflow.value.name : (currentWorkflow.value ? currentWorkflow.value.name : null),
        positivePrompt: mainPrompt,
        negativePrompt: dynamicPrompts.value.length > 1 ? dynamicPrompts.value[1].currentValue : '',
        nodeInfoList: nodeInfoList,
        taskType: selectedTaskType.value || 'Standard',
        customPrompt: isCustom ? customWorkflow.value.prompt : null
      };

      if (publicConfig.value.requireLoginToGenerate && !currentUser.value) {
        showToastNotification('当前系统已开启强制登录，请先登录或注册账号后再生成', 'warning');
        openAuthModal('signin');
        isGenerating.value = false;
        return;
      }

      try {
        const res = await authFetch('/api/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.status === 'ok') {
          activeOutputIndex.value = 0;
          await refreshTasks();
          await fetchCurrentUser();
        } else {
          showToastNotification('任务创建失败: ' + (data.detail || JSON.stringify(data)), 'error');
          isGenerating.value = false;
        }
      } catch (err) {
        showToastNotification('提交任务请求异常: ' + err.message, 'error');
        isGenerating.value = false;
      }
    };

    const formatTime = (ts) => {
      if (!ts) return '';
      const d = new Date(ts * 1000);
      return d.toLocaleString('zh-CN', { hour12: false });
    };

    const switchKey = async (keyId) => {
      try {
        const res = await authFetch(`/api/keys/${keyId}/activate`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
          keys.value = data.keys || [];
          activeKeyId.value = data.activeKeyId || '';
          const activeItem = keys.value.find(k => k.id === activeKeyId.value);
          if (activeItem) {
            activeKeyName.value = activeItem.name;
            activeMaskedKey.value = activeItem.maskedKey;
          }
          showKeyDropdown.value = false;
        }
      } catch (err) {
        showToastNotification('切换密钥失败: ' + err.message, 'error');
      }
    };

    const addNewKey = async () => {
      if (!newKeyForm.value.apiKey || !newKeyForm.value.apiKey.trim()) {
        showToastNotification('请填入有效的 RunningHub API Key', 'warning');
        return;
      }
      isAddingKey.value = true;
      try {
        const res = await authFetch('/api/keys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(newKeyForm.value)
        });
        const data = await res.json();
        if (data.status === 'ok') {
          newKeyForm.value = { name: '', apiKey: '', note: '', setActive: true };
          showKeyPlainText.value = false;
          await fetchConfig();
          showToastNotification('API Key 已安全加密入库！', 'success');
        } else {
          showToastNotification('添加失败: ' + (data.detail || '未知错误'), 'error');
        }
      } catch (err) {
        showToastNotification('添加密钥异常: ' + err.message, 'error');
      } finally {
        isAddingKey.value = false;
      }
    };

    const deleteKey = async (keyId, keyName) => {
      const ok = await confirmAction({
        title: '删除 API 密钥',
        message: `确定要删除密钥【${keyName || keyId}】吗？删除后将无法恢复。`,
        confirmText: '确认删除',
        type: 'danger'
      });
      if (!ok) return;
      try {
        const res = await authFetch(`/api/keys/${keyId}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.status === 'ok') {
          await fetchConfig();
          showToastNotification('API 密钥已成功删除', 'success');
        }
      } catch (err) {
        showToastNotification('删除失败: ' + err.message, 'error');
      }
    };

    const testKey = async (keyId) => {
      testingKeyId.value = keyId;
      try {
        const res = await authFetch(`/api/keys/${keyId}/test`, { method: 'POST' });
        const data = await res.json();
        keyTestResult.value[keyId] = {
          valid: data.valid,
          message: data.message
        };
      } catch (err) {
        keyTestResult.value[keyId] = {
          valid: false,
          message: '请求异常: ' + err.message
        };
      } finally {
        testingKeyId.value = null;
      }
    };

    const copyMasked = (text) => {
      if (!text) return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text);
        showToastNotification('已复制脱敏 Key: ' + text, 'success');
      } else {
        showToastNotification('脱敏 Key: ' + text, 'info');
      }
    };

    // 保存旧版设置兼容
    const saveSettings = async () => {
      try {
        const res = await authFetch('/api/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ apiKey: config.value.apiKey })
        });
        const data = await res.json();
        if (data.status === 'ok') {
          await fetchConfig();
          showToastNotification('API Key 保存成功！', 'success');
        }
      } catch (err) {
        showToastNotification('保存失败: ' + err.message, 'error');
      }
    };

    // 自动探测新填入的工作流
    const autoDetectWorkflow = async () => {
      if (!newWf.value.id) {
        showToastNotification('请先输入工作流 ID', 'warning');
        return;
      }
      isDetecting.value = true;
      try {
        const res = await authFetch('/api/workflows/inspect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ workflowId: newWf.value.id })
        });
        const data = await res.json();
        if (data.status === 'ok') {
          if (!newWf.value.name) {
            newWf.value.name = `工作流 ${newWf.value.id}`;
          }
          if (!newWf.value.description) {
            newWf.value.description = `共解析 ${data.totalNodes} 个节点，包含自适应提示词与全量可调参数。`;
          }
          showToastNotification(`探测成功！已识别拓扑架构（共 ${data.totalNodes} 个节点）`, 'success');
        } else {
          showToastNotification('云端探测失败: ' + (data.detail || '请确认工作流 ID 是否正确或已公开'), 'error');
        }
      } catch (err) {
        showToastNotification('探测请求发生错误: ' + err.message, 'error');
      } finally {
        isDetecting.value = false;
      }
    };

    // 保存新工作流
    const isAddingWorkflow = ref(false);
    const saveNewWorkflow = async () => {
      if (!newWf.value.id || !newWf.value.name) {
        showToastNotification('请填写工作流 ID 与名称', 'warning');
        return;
      }

      isAddingWorkflow.value = true;
      try {
        const res = await authFetch('/api/workflows', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(newWf.value)
        });
        const data = await res.json();
        if (res.ok && data.status === 'ok') {
          await fetchConfig();
          showAddWorkflowModal.value = false;
          const addedId = newWf.value.id;
          newWf.value = { id: '', name: '', category: '视频生成', description: '' };
          selectedWorkflowId.value = addedId;
          await loadWorkflowSchema(addedId);
          activeTab.value = 'studio';
          showToastNotification('工作流已成功添加并生效！', 'success');
        } else {
          showToastNotification('添加失败: ' + (data.detail || JSON.stringify(data)), 'error');
        }
      } catch (err) {
        showToastNotification('保存请求发生网络异常: ' + err.message, 'error');
      } finally {
        isAddingWorkflow.value = false;
      }
    };

    // 删除工作流
    const deleteWorkflow = async (id) => {
      const ok = await confirmAction({
        title: '移除工作流',
        message: `确定要将工作流 ${id} 从快捷列表中移除吗？`,
        confirmText: '确认移除',
        type: 'danger'
      });
      if (!ok) return;
      try {
        await authFetch(`/api/workflows/${id}`, { method: 'DELETE' });
        await fetchConfig();
        showToastNotification('工作流已成功移除', 'success');
      } catch (err) {
        showToastNotification('删除失败: ' + err.message, 'error');
      }
    };

    const inspectWorkflow = async (wfId) => {
      await loadWorkflowSchema(wfId);
      selectedWorkflowId.value = wfId;
      activeTab.value = 'studio';
    };

    const selectAndGoToStudio = async (id) => {
      customWorkflow.value = null;
      selectedWorkflowId.value = id;
      await loadWorkflowSchema(id);
      activeTab.value = 'studio';
      window.scrollTo({ top: 0, behavior: 'smooth' });
    };

    // 用户从个人画廊移除成果（软删除，仅对自己隐藏，管理员后台可见）
    const deleteGalleryItem = async (taskId, filename) => {
      if (!filename && taskId) {
        filename = taskId;
        taskId = '';
      }
      const ok = await confirmAction({
        title: '移除生成成果',
        message: '确定要从您的个人画廊中移除这个作品吗？移除后将不再显示。',
        confirmText: '确认移除',
        type: 'danger'
      });
      if (!ok) return;
      try {
        let url = `/api/gallery/${encodeURIComponent(filename)}`;
        if (taskId) {
          url = `/api/gallery/${encodeURIComponent(taskId)}/${encodeURIComponent(filename)}`;
        }
        const res = await authFetch(url, { method: 'DELETE' });
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || '删除失败');
        }
        // 关键：立即从前端响应式数组中移除，确保画廊卡片瞬间消失！
        gallery.value = gallery.value.filter(g => {
          if (taskId && g.taskId === taskId) {
            return g.filename !== filename && !g.url.includes(filename);
          }
          return g.filename !== filename && !g.url.includes(filename);
        });
        lastGalleryHash = '';
        showToastNotification('成果已从您的个人画廊中成功移除', 'success');
        await refreshGallery();
      } catch (err) {
        showToastNotification('移除成果失败: ' + err.message, 'error');
      }
    };

    const formatFileSize = (bytes) => {
      if (!bytes || isNaN(bytes) || bytes <= 0) return '';
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    };

    const formatDuration = (sec) => {
      if (!sec || isNaN(sec)) return '00:00';
      const s = Math.floor(sec);
      const m = Math.floor(s / 60);
      const rem = s % 60;
      return `${m.toString().padStart(2, '0')}:${rem.toString().padStart(2, '0')}`;
    };

    const reusePromptToStudio = (prompt) => {
      if (!prompt) return;
      if (activeWorkflow.value && activeWorkflow.value.fields) {
        if ('prompt' in activeWorkflow.value.fields) activeWorkflow.value.fields.prompt = prompt;
        if ('positive_prompt' in activeWorkflow.value.fields) activeWorkflow.value.fields.positive_prompt = prompt;
        if ('positive' in activeWorkflow.value.fields) activeWorkflow.value.fields.positive = prompt;
      }
      activeTab.value = 'studio';
      window.scrollTo({ top: 0, behavior: 'smooth' });
      showToastNotification('提示词已填入工作台，可直接生成同款', 'success');
    };

    const copyToClipboard = async (text, msg = '已复制到剪贴板') => {
      try {
        await navigator.clipboard.writeText(text);
        showToastNotification(msg, 'success');
      } catch {
        showToastNotification('复制失败，请手动选择复制', 'error');
      }
    };

    const openLightbox = (url) => {
      lightboxUrl.value = url;
    };

    // 浏览器端纯前端直链下载 (零经过服务器，由浏览器直接请求 RunningHub CDN)
    const downloadMedia = async (url, defaultFilename) => {
      if (!url) return;
      if (url.startsWith('data:')) {
        const a = document.createElement('a');
        a.href = url;
        a.download = defaultFilename || 'preview.png';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        return;
      }

      const isVideo = isVideoUrl(url) || (defaultFilename && isVideoUrl(defaultFilename));
      const isAudio = isAudioUrl(url) || (defaultFilename && isAudioUrl(defaultFilename));
      const fallbackName = defaultFilename || (isVideo ? 'output.mp4' : (isAudio ? 'output.mp3' : 'output.png'));

      try {
        const resp = await fetch(url, { mode: 'cors' });
        if (!resp.ok) throw new Error("direct fetch failed");
        const blob = await resp.blob();
        const blobUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = blobUrl;
        a.download = fallbackName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(blobUrl), 10000);
      } catch (err) {
        const a = document.createElement('a');
        a.href = url;
        a.target = '_blank';
        a.download = fallbackName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      }
    };

    const cancelTask = async (taskId) => {
      if (!taskId) return;
      const ok = await confirmAction({
        title: '取消任务',
        message: '确定要中途取消该任务吗？云端正在渲染的计算也将被终止，已扣除的算力点数将自动原路全额退还。',
        confirmText: '确认取消',
        type: 'danger'
      });
      if (!ok) return;
      try {
        const res = await authFetch(`/api/tasks/${taskId}/cancel`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
          isGenerating.value = false;
          showToastNotification('任务已终止，算力已退还', 'success');
          await refreshTasks();
        } else {
          showToastNotification('取消失败: ' + (data.detail || data.message || '未知错误'), 'error');
        }
      } catch (err) {
        showToastNotification('取消请求异常: ' + err.message, 'error');
      }
    };

    // ================= 认证与用户操作方法 =================
    const fetchPublicConfig = async () => {
      try {
        const res = await fetch('/api/auth/public-config');
        if (res.ok) {
          publicConfig.value = await res.json();
        }
      } catch (err) {
        console.error('Failed to fetch public auth config:', err);
      }
    };

    // ================= 官方公告与资讯状态 =================
    const announcements = ref([]);
    const selectedAnnoTag = ref('全部');

    const filteredAnnouncements = computed(() => {
      if (selectedAnnoTag.value === '全部') {
        return announcements.value;
      }
      return announcements.value.filter(a => a.tag === selectedAnnoTag.value);
    });

    const fetchAnnouncements = async () => {
      try {
        const res = await fetch('/api/announcements');
        if (res.ok) {
          announcements.value = await res.json();
        }
      } catch (err) {
        console.error('Failed to fetch announcements:', err);
      }
    };

    let userEventSource = null;

    const initUserEventStream = () => {
      if (!currentUser.value) return;
      if (userEventSource) {
        try { userEventSource.close(); } catch(e){}
      }

      const token = localStorage.getItem('rh_auth_token') || '';
      const sseUrl = `/api/events/user?token=${encodeURIComponent(token)}`;
      userEventSource = new EventSource(sseUrl);

      userEventSource.onmessage = (event) => {
        try {
          if (!event.data) return;
          const payload = JSON.parse(event.data);

          // 1. 核心：0.1 秒即时秒踢与强制退出 (KICK_OFF)
          if (payload.type === 'KICK_OFF') {
            console.warn('[Security Event] Received KICK_OFF signal from server:', payload);
            if (userEventSource) {
              userEventSource.close();
              userEventSource = null;
            }
            localStorage.removeItem('rh_auth_token');
            localStorage.removeItem('rh_auth_user');
            currentUser.value = null;
            const reason = payload.data?.reason || '您的账号已被管理员停用，已强制下线。';
            showToastNotification(`安全通知：${reason}`, 'error');
            setTimeout(() => {
              window.location.href = '/sign-in';
            }, 1800);
          }

          // 2. 核心：算力点数 0 延迟实时跳变 (POINTS_UPDATED)
          else if (payload.type === 'POINTS_UPDATED') {
            const newPoints = payload.data?.points;
            if (newPoints !== undefined && currentUser.value) {
              const oldPoints = currentUser.value.points;
              currentUser.value.points = newPoints;
              console.log(`[SSE] Points updated dynamically: ${oldPoints} -> ${newPoints}`);
              showToastNotification(`🪙 算力余额已实时更新为: ${newPoints} 点`);
            }
          }
        } catch(e) {
          // 心跳或格式忽略
        }
      };

      userEventSource.onerror = (err) => {
        // SSE 会在连接中断时由浏览器底层自动发起静默重连
      };
    };

    const fetchCurrentUser = async () => {
      const token = localStorage.getItem('rh_auth_token');
      if (!token) {
        currentUser.value = null;
        window.location.href = '/sign-in?redirect=' + encodeURIComponent(window.location.pathname + window.location.search);
        return;
      }
      try {
        const res = await authFetch('/api/auth/me');
        if (res.ok) {
          currentUser.value = await res.json();
          initUserEventStream();
        } else if (res.status === 401 || res.status === 403) {
          localStorage.removeItem('rh_auth_token');
          currentUser.value = null;
          window.location.href = '/sign-in?redirect=' + encodeURIComponent(window.location.pathname + window.location.search);
        }
      } catch (err) {
        console.error('Failed to fetch current user:', err);
      }
    };

    const openAuthModal = (tab = 'signin') => {
      authTab.value = tab;
      authError.value = '';
      authSuccessMsg.value = '';
      authForm.value.turnstileToken = '';
      showAuthModal.value = true;
      renderTurnstileWidget();
    };

    const closeAuthModal = () => {
      showAuthModal.value = false;
      authError.value = '';
      authSuccessMsg.value = '';
      if (turnstileWidgetId.value !== null && window.turnstile) {
        try { window.turnstile.remove(turnstileWidgetId.value); } catch(e){}
        turnstileWidgetId.value = null;
      }
    };

    const renderTurnstileWidget = () => {
      if (!publicConfig.value.turnstileEnabled || !publicConfig.value.turnstileSiteKey) {
        return;
      }
      setTimeout(() => {
        const container = document.getElementById('turnstile-container');
        if (!container || !window.turnstile) return;
        if (turnstileWidgetId.value !== null) {
          try { window.turnstile.remove(turnstileWidgetId.value); } catch(e){}
          turnstileWidgetId.value = null;
        }
        try {
          turnstileWidgetId.value = window.turnstile.render('#turnstile-container', {
            sitekey: publicConfig.value.turnstileSiteKey,
            theme: 'dark',
            callback: (token) => {
              authForm.value.turnstileToken = token;
            },
            'expired-callback': () => {
              authForm.value.turnstileToken = '';
            },
            'error-callback': () => {
              authForm.value.turnstileToken = '';
            }
          });
        } catch(e) {
          console.warn('Turnstile render warning:', e);
        }
      }, 250);
    };

    const submitAuth = async () => {
      authError.value = '';
      authSuccessMsg.value = '';

      if (authTab.value === 'signup') {
        if (!authForm.value.username || authForm.value.username.trim().length < 3) {
          authError.value = '用户名长度不能少于 3 个字符';
          return;
        }
        if (!authForm.value.password || authForm.value.password.length < 6) {
          authError.value = '密码长度不能少于 6 位';
          return;
        }
        if (authForm.value.password !== authForm.value.confirmPassword) {
          authError.value = '两次输入的密码不一致，请仔细核对';
          return;
        }
        if (publicConfig.value.turnstileEnabled && publicConfig.value.turnstileSiteKey && !authForm.value.turnstileToken) {
          authError.value = '请先勾选并完成 Cloudflare 人机安全验证';
          return;
        }

        authLoading.value = true;
        try {
          const res = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              username: authForm.value.username.trim(),
              email: authForm.value.email.trim(),
              password: authForm.value.password,
              turnstileToken: authForm.value.turnstileToken
            })
          });
          const data = await res.json();
          if (res.ok && data.status === 'ok') {
            localStorage.setItem('rh_auth_token', data.token);
            currentUser.value = data.user;
            authSuccessMsg.value = data.message || '注册成功！';
            await fetchPublicConfig();
            await refreshTasks();
            await refreshGallery();
            setTimeout(() => {
              closeAuthModal();
            }, 1200);
          } else {
            authError.value = data.detail || data.message || '注册失败';
            if (window.turnstile && turnstileWidgetId.value !== null) {
              window.turnstile.reset(turnstileWidgetId.value);
            }
          }
        } catch(err) {
          authError.value = '网络请求失败: ' + err.message;
        } finally {
          authLoading.value = false;
        }
      } else {
        // 登录模式
        if (!authForm.value.identifier) {
          authError.value = '请输入用户名或邮箱地址';
          return;
        }
        if (!authForm.value.password) {
          authError.value = '请输入登录密码';
          return;
        }
        if (publicConfig.value.turnstileEnabled && publicConfig.value.turnstileSiteKey && !authForm.value.turnstileToken) {
          authError.value = '请先完成 Cloudflare 人机安全验证';
          return;
        }

        authLoading.value = true;
        try {
          const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              identifier: authForm.value.identifier.trim(),
              password: authForm.value.password,
              turnstileToken: authForm.value.turnstileToken
            })
          });
          const data = await res.json();
          if (res.ok && data.status === 'ok') {
            localStorage.setItem('rh_auth_token', data.token);
            currentUser.value = data.user;
            authSuccessMsg.value = '登录成功，欢迎回来！';
            await refreshTasks();
            await refreshGallery();
            setTimeout(() => {
              closeAuthModal();
            }, 800);
          } else {
            authError.value = data.detail || data.message || '登录失败';
            if (window.turnstile && turnstileWidgetId.value !== null) {
              window.turnstile.reset(turnstileWidgetId.value);
            }
          }
        } catch(err) {
          authError.value = '网络请求失败: ' + err.message;
        } finally {
          authLoading.value = false;
        }
      }
    };

    const logout = async () => {
      if (userEventSource) {
        try { userEventSource.close(); } catch(e){}
        userEventSource = null;
      }
      try {
        await authFetch('/api/auth/logout', { method: 'POST' });
      } catch(e){}
      localStorage.removeItem('rh_auth_token');
      localStorage.removeItem('rh_auth_user');
      currentUser.value = null;
      showUserDropdown.value = false;
      window.location.href = '/sign-in';
    };

    const openChangePwdModal = () => {
      pwdForm.value = { oldPassword: '', newPassword: '', confirmPassword: '' };
      pwdError.value = '';
      pwdSuccessMsg.value = '';
      showChangePwdModal.value = true;
      showUserDropdown.value = false;
    };

    const submitChangePassword = async () => {
      pwdError.value = '';
      pwdSuccessMsg.value = '';
      if (!pwdForm.value.oldPassword) {
        pwdError.value = '请输入当前原密码';
        return;
      }
      if (!pwdForm.value.newPassword || pwdForm.value.newPassword.length < 6) {
        pwdError.value = '新密码长度不能少于 6 位';
        return;
      }
      if (pwdForm.value.newPassword !== pwdForm.value.confirmPassword) {
        pwdError.value = '两次输入的新密码不一致';
        return;
      }
      pwdLoading.value = true;
      try {
        const res = await authFetch('/api/auth/change-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            oldPassword: pwdForm.value.oldPassword,
            newPassword: pwdForm.value.newPassword
          })
        });
        const data = await res.json();
        if (res.ok && data.status === 'ok') {
          pwdSuccessMsg.value = '密码修改成功！';
          setTimeout(() => {
            showChangePwdModal.value = false;
          }, 1200);
        } else {
          pwdError.value = data.detail || '修改失败';
        }
      } catch(err) {
        pwdError.value = '请求异常: ' + err.message;
      } finally {
        pwdLoading.value = false;
      }
    };

    // ================= 开发者管理后台操作 =================
    const switchTab = (tab) => {
      activeTab.value = tab;
      window.scrollTo({ top: 0, behavior: 'smooth' });
      if (tab === 'admin') {
        fetchAdminOverview();
        fetchAdminUsers();
        fetchAdminSystem();
      }
    };

    const fetchAdminOverview = async () => {
      try {
        const res = await authFetch('/api/admin/overview');
        if (res.ok) {
          adminOverview.value = await res.json();
        }
      } catch(e){}
    };

    const fetchAdminUsers = async () => {
      adminLoading.value = true;
      try {
        const res = await authFetch('/api/admin/users');
        if (res.ok) {
          adminUsers.value = await res.json();
        }
      } catch(e){}
      finally {
        adminLoading.value = false;
      }
    };

    const fetchAdminSystem = async () => {
      try {
        const res = await authFetch('/api/admin/system');
        if (res.ok) {
          const sys = await res.json();
          adminSystem.value = {
            ...sys,
            turnstileSecretKey: ''
          };
        }
      } catch(e){}
    };

    const saveAdminSystem = async () => {
      try {
        const payload = {
          siteTitle: adminSystem.value.siteTitle,
          turnstileEnabled: adminSystem.value.turnstileEnabled,
          turnstileSiteKey: adminSystem.value.turnstileSiteKey,
          allowRegistration: adminSystem.value.allowRegistration,
          defaultUserPoints: adminSystem.value.defaultUserPoints,
          requireLoginToGenerate: adminSystem.value.requireLoginToGenerate
        };
        if (adminSystem.value.turnstileSecretKey && adminSystem.value.turnstileSecretKey.trim()) {
          payload.turnstileSecretKey = adminSystem.value.turnstileSecretKey.trim();
        }
        const res = await authFetch('/api/admin/system', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (res.ok) {
          showToastNotification('系统与安全设置已成功保存！', 'success');
          await fetchAdminSystem();
          await fetchPublicConfig();
        } else {
          const err = await res.json();
          showToastNotification('保存失败: ' + (err.detail || '未知错误'), 'error');
        }
      } catch(err) {
        showToastNotification('请求异常: ' + err.message, 'error');
      }
    };

    const fetchAdminTasks = async () => {
      adminLoading.value = true;
      try {
        const res = await authFetch('/api/admin/tasks');
        if (res.ok) {
          adminTasks.value = await res.json();
        }
      } catch(e){}
      finally {
        adminLoading.value = false;
      }
    };

    const openEditUserModal = (user) => {
      editingUser.value = user;
      editUserForm.value = {
        role: user.role,
        points: user.points,
        isActive: user.isActive !== false,
        newPassword: ''
      };
    };

    const submitEditUser = async () => {
      if (!editingUser.value) return;
      try {
        const payload = {
          role: editUserForm.value.role,
          points: editUserForm.value.points,
          isActive: editUserForm.value.isActive
        };
        if (editUserForm.value.newPassword && editUserForm.value.newPassword.trim().length >= 6) {
          payload.newPassword = editUserForm.value.newPassword.trim();
        }
        const res = await authFetch(`/api/admin/users/${editingUser.value.id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (res.ok) {
          editingUser.value = null;
          showToastNotification('用户信息修改成功！', 'success');
          await fetchAdminUsers();
        } else {
          const err = await res.json();
          showToastNotification('修改失败: ' + (err.detail || '未知错误'), 'error');
        }
      } catch(err) {
        showToastNotification('修改失败: ' + err.message, 'error');
      }
    };

    const deleteUser = async (userId, username) => {
      const ok = await confirmAction({
        title: '彻底删除用户',
        message: `确定要彻底删除用户【${username}】吗？此操作无法撤销！`,
        confirmText: '彻底删除',
        type: 'danger'
      });
      if (!ok) return;
      try {
        const res = await authFetch(`/api/admin/users/${userId}`, { method: 'DELETE' });
        if (res.ok) {
          showToastNotification('用户已成功删除', 'success');
          await fetchAdminUsers();
        } else {
          const err = await res.json();
          showToastNotification('删除失败: ' + (err.detail || '未知错误'), 'error');
        }
      } catch(err) {
        showToastNotification('删除失败: ' + err.message, 'error');
      }
    };

    const statusBadgeClass = (status) => {
      switch (status) {
        case 'SUCCESS':
          return 'bg-emerald-950 text-emerald-400 border border-emerald-800';
        case 'RUNNING':
        case 'QUEUED':
          return 'bg-amber-950 text-amber-400 border border-amber-800 animate-pulse';
        case 'FAILED':
        case 'TIMEOUT':
          return 'bg-red-950 text-red-400 border border-red-800';
        case 'CANCELLED':
          return 'bg-slate-800/80 text-slate-400 border border-slate-700';
        default:
          return 'bg-slate-800 text-slate-400';
      }
    };

    let galleryTimer = null;
    onMounted(async () => {
      await fetchPublicConfig();
      await fetchCurrentUser();
      await fetchAnnouncements();
      await fetchConfig();
      await refreshTasks();
      await refreshGallery();

      // 智能自适应静默轮询：
      // 1. 标签页处于后台静默或切换到其他窗口时自动跳过轮询，彻底释放浏览器线程
      // 2. 有任务运行中时按 3 秒频率轮询任务与画廊；任务空闲时画廊每 10 秒低频同步
      pollingTimer = setInterval(async () => {
        if (document.hidden) return;
        await refreshTasks();
        const hasActive = (tasks.value || []).some(t => t.status === 'RUNNING' || t.status === 'QUEUED');
        if (hasActive) {
          await refreshGallery();
        }
      }, 3000);

      galleryTimer = setInterval(() => {
        if (!document.hidden) refreshGallery();
      }, 10000);
    });

    onUnmounted(() => {
      if (pollingTimer) clearInterval(pollingTimer);
      if (galleryTimer) clearInterval(galleryTimer);
      if (userEventSource) {
        try { userEventSource.close(); } catch(e){}
        userEventSource = null;
      }
    });

    return {
      toastState,
      showToastNotification,
      confirmModal,
      confirmAction,
      activeTab,
      switchTab,
      config,
      keys,
      activeKeyId,
      activeKeyName,
      activeMaskedKey,
      showKeyDropdown,
      showKeyPlainText,
      isAddingKey,
      testingKeyId,
      keyTestResult,
      newKeyForm,
      formatTime,
      switchKey,
      addNewKey,
      deleteKey,
      testKey,
      copyMasked,
      workflows,
      workflowSearch,
      selectedWfCategory,
      workflowCategories,
      filteredWorkflows,
      officialWorkflows,
      userWorkflows,
      selectedWorkflowId,
      currentWorkflow,
      tasks,
      gallery,
      latestTask,
      activeOutputIndex,
      currentDisplayOutput,
      runningTasksCount,
      isGenerating,
      isDetecting,
      isLoadingSchema,
      lightboxUrl,
      showAddWorkflowModal,
      dynamicSchema,
      dynamicSchemaTotalNodes,
      dynamicPrompts,
      dynamicSampler,
      dynamicLatent,
      dynamicImages,
      dynamicVideos,
      dynamicAudios,
      dynamicQuality,
      allEditableNodes,
      customWorkflow,
      workflowFileInput,
      triggerUploadWorkflowFile,
      clearCustomWorkflow,
      handleWorkflowFileSelected,
      nodeOverrides,
      originalDefaults,
      showAllNodes,
      allNodesSearch,
      filteredAllNodes,
      modifiedParamsCount,
      workflowIssues,
      applyRecommendedFixes,
      newWf,
      isVideoUrl,
      isVideoOutput,
      isAudioUrl,
      isAudioOutput,
      isFieldModified,
      resetField,
      resetNode,
      fetchConfig,
      refreshTasks,
      refreshGallery,
      onWorkflowChange,
      loadWorkflowSchema,
      randomizeDynamicSeed,
      handleNodeImageUpload,
      handleNodeVideoUpload,
      handleNodeAudioUpload,
      submitDynamicGeneration,
      saveSettings,
      saveNewWorkflow,
      isAddingWorkflow,
      autoDetectWorkflow,
      deleteWorkflow,
      inspectWorkflow,
      selectAndGoToStudio,
      deleteGalleryItem,
      downloadMedia,
      openLightbox,
      formatFileSize,
      formatDuration,
      reusePromptToStudio,
      copyToClipboard,
      formatTime,
      cancelTask,
      selectedTaskType,
      statusBadgeClass,
      // 用户鉴权与管理
      currentUser,
      publicConfig,
      isBroadcastDismissed,
      dismissBroadcast,
      showAuthModal,
      authTab,
      authForm,
      authLoading,
      authError,
      authSuccessMsg,
      showUserDropdown,
      turnstileWidgetId,
      showChangePwdModal,
      pwdForm,
      pwdLoading,
      pwdError,
      pwdSuccessMsg,
      openAuthModal,
      closeAuthModal,
      submitAuth,
      logout,
      openChangePwdModal,
      submitChangePassword,
      // 官方公告与动态
      announcements,
      selectedAnnoTag,
      filteredAnnouncements,
      fetchAnnouncements,
      // 开发者后台
      adminTab,
      adminOverview,
      adminUsers,
      adminTasks,
      adminSystem,
      adminLoading,
      adminSearchUser,
      editingUser,
      editUserForm,
      fetchAdminOverview,
      fetchAdminUsers,
      fetchAdminSystem,
      saveAdminSystem,
      fetchAdminTasks,
      openEditUserModal,
      submitEditUser,
      deleteUser
    };
  }
}).mount('#app');