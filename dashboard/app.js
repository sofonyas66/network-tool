/**
 * app.js — NetFP 3D Dashboard
 * Three.js scene: host spheres orbit around a central node.
 * Open ports appear as smaller orbiting satellite nodes.
 * Real-time polling of /results every 2 seconds.
 */

// ── OS color map ──────────────────────────────────────────────────────────────
const OS_COLORS = {
  linux:   0x3dd6f5,   // cyan
  windows: 0x4a9eff,   // blue
  bsd:     0x00e5a0,   // green
  virt:    0xe040fb,   // magenta
  unknown: 0x64748b,   // grey
};

function osColor(fingerprint) {
  if (!fingerprint) return OS_COLORS.unknown;
  const os = (fingerprint.os_guess || '').toLowerCase();
  if (fingerprint.virtualized)         return OS_COLORS.virt;
  if (os.includes('linux'))            return OS_COLORS.linux;
  if (os.includes('windows'))          return OS_COLORS.windows;
  if (os.includes('bsd') || os.includes('macos')) return OS_COLORS.bsd;
  return OS_COLORS.unknown;
}

// ── Three.js setup ────────────────────────────────────────────────────────────
const canvas   = document.getElementById('glcanvas');
const wrap     = document.getElementById('canvasWrap');
const tooltip  = document.getElementById('nodeTooltip');

const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
renderer.setPixelRatio(window.devicePixelRatio);
renderer.setClearColor(0x000000, 0);

const scene  = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(55, 1, 0.1, 1000);
camera.position.set(0, 0, 28);

// Ambient + directional lights
scene.add(new THREE.AmbientLight(0xffffff, 0.3));
const dir = new THREE.DirectionalLight(0x3dd6f5, 1.2);
dir.position.set(10, 20, 10);
scene.add(dir);
const dir2 = new THREE.DirectionalLight(0xe040fb, 0.6);
dir2.position.set(-10, -10, -5);
scene.add(dir2);

// Starfield background
(function makeStars() {
  const geo = new THREE.BufferGeometry();
  const pos = [];
  for (let i = 0; i < 1800; i++) {
    pos.push((Math.random() - 0.5) * 300,
             (Math.random() - 0.5) * 300,
             (Math.random() - 0.5) * 300);
  }
  geo.setAttribute('position', new THREE.Float32BufferAttribute(pos, 3));
  const mat = new THREE.PointsMaterial({ color: 0x94a3b8, size: 0.18 });
  scene.add(new THREE.Points(geo, mat));
})();

// Central "hub" node
const hubGeo = new THREE.SphereGeometry(1.2, 32, 32);
const hubMat = new THREE.MeshPhongMaterial({
  color: 0x3dd6f5, emissive: 0x0a4a55, shininess: 120,
  transparent: true, opacity: 0.85,
});
const hub = new THREE.Mesh(hubGeo, hubMat);
scene.add(hub);

// Pulsing ring around hub
const ringGeo = new THREE.RingGeometry(1.8, 2.2, 64);
const ringMat = new THREE.MeshBasicMaterial({
  color: 0x3dd6f5, side: THREE.DoubleSide,
  transparent: true, opacity: 0.3,
});
const hubRing = new THREE.Mesh(ringGeo, ringMat);
hubRing.rotation.x = Math.PI / 2;
scene.add(hubRing);

// ── Scene graph for host nodes ────────────────────────────────────────────────
let hostNodes   = [];    // { mesh, portMeshes[], orbitAngle, orbitRadius, label, data }
let scanData    = [];
let selectedIdx = null;

// Raycaster for mouse interaction
const raycaster = new THREE.Raycaster();
const mouse     = new THREE.Vector2(-9, -9);
let   hoveredNode = null;

// ── Build / rebuild scene ─────────────────────────────────────────────────────
function clearScene() {
  hostNodes.forEach(n => {
    scene.remove(n.mesh);
    n.portMeshes.forEach(pm => scene.remove(pm));
    if (n.orbitLine) scene.remove(n.orbitLine);
    n.connLine && scene.remove(n.connLine);
  });
  hostNodes = [];
}

function buildScene(data) {
  clearScene();
  if (!data || data.length === 0) return;

  const total = data.length;
  data.forEach((host, idx) => {
    const angle  = (idx / total) * Math.PI * 2;
    const radius = 6 + Math.min(total * 0.8, 10);
    const x = Math.cos(angle) * radius;
    const z = Math.sin(angle) * radius;
    const y = (Math.random() - 0.5) * 4;

    // Host sphere
    const col   = openPortsColor(host);
    const geo   = new THREE.SphereGeometry(0.7, 24, 24);
    const mat   = new THREE.MeshPhongMaterial({
      color: col, emissive: new THREE.Color(col).multiplyScalar(0.2),
      shininess: 80,
    });
    const mesh  = new THREE.Mesh(geo, mat);
    mesh.position.set(x, y, z);
    scene.add(mesh);

    // Orbit guide ring
    const oCurve  = new THREE.EllipseCurve(0, 0, radius, radius, 0, Math.PI * 2, false, 0);
    const oPoints = oCurve.getPoints(80);
    const oGeo    = new THREE.BufferGeometry().setFromPoints(
      oPoints.map(p => new THREE.Vector3(p.x, y, p.y))
    );
    const oLine   = new THREE.Line(oGeo, new THREE.LineBasicMaterial({
      color: col, transparent: true, opacity: 0.08,
    }));
    scene.add(oLine);

    // Connection line: hub → host
    const connGeo  = new THREE.BufferGeometry().setFromPoints([
      new THREE.Vector3(0, 0, 0),
      new THREE.Vector3(x, y, z),
    ]);
    const connLine = new THREE.Line(connGeo, new THREE.LineBasicMaterial({
      color: col, transparent: true, opacity: 0.25,
    }));
    scene.add(connLine);

    // Port satellite nodes
    const openPorts = (host.ports || []).filter(p => p.state === 'open');
    const portMeshes = [];
    openPorts.forEach((port, pi) => {
      const pa = (pi / Math.max(openPorts.length, 1)) * Math.PI * 2;
      const pr = 1.5;
      const px = x + Math.cos(pa) * pr;
      const pz = z + Math.sin(pa) * pr;
      const pGeo = new THREE.SphereGeometry(0.18, 12, 12);
      const fp   = port.fingerprint;
      const pc   = fp ? osColor(fp) : OS_COLORS.unknown;
      const pMat = new THREE.MeshPhongMaterial({ color: pc, emissive: pc, emissiveIntensity: 0.4 });
      const pMesh = new THREE.Mesh(pGeo, pMat);
      pMesh.position.set(px, y, pz);
      pMesh.userData = { isPort: true, port: port.port, host: host.target };
      scene.add(pMesh);
      portMeshes.push(pMesh);

      // Port connection line
      const plGeo = new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(x, y, z),
        new THREE.Vector3(px, y, pz),
      ]);
      scene.add(new THREE.Line(plGeo, new THREE.LineBasicMaterial({
        color: pc, transparent: true, opacity: 0.4,
      })));
    });

    hostNodes.push({
      mesh, portMeshes, orbitLine: oLine, connLine,
      orbitAngle: angle, orbitRadius: radius, orbitY: y,
      data: host,
    });
  });
}

function openPortsColor(host) {
  const openPorts = (host.ports || []).filter(p => p.state === 'open');
  if (!openPorts.length) return OS_COLORS.unknown;
  // Use fingerprint of first open port for host color
  const fp = openPorts[0].fingerprint;
  return osColor(fp);
}

// ── UI helpers ────────────────────────────────────────────────────────────────
function updateStats(data) {
  let totalOpen = 0, totalVirt = 0, totalLB = 0;
  data.forEach(h => {
    const open  = (h.ports || []).filter(p => p.state === 'open');
    totalOpen += open.length;
    open.forEach(p => {
      if (p.fingerprint?.virtualized)              totalVirt++;
      if (p.fingerprint?.load_balancer_suspected)  totalLB++;
    });
  });
  document.getElementById('statHosts').textContent = data.length;
  document.getElementById('statOpen').textContent  = totalOpen;
  document.getElementById('statVirt').textContent  = totalVirt;
  document.getElementById('statLB').textContent    = totalLB;
  document.getElementById('hostCount').textContent = data.length;
}

function updateHostList(data) {
  const list = document.getElementById('hostList');
  list.innerHTML = '';
  data.forEach((host, idx) => {
    const openPorts = (host.ports || []).filter(p => p.state === 'open');
    const fp = openPorts[0]?.fingerprint;
    const os = fp?.os_guess || 'Unknown';

    const card = document.createElement('div');
    card.className = 'host-card' + (idx === selectedIdx ? ' selected' : '');
    card.innerHTML = `
      <div class="host-ip">${host.target}</div>
      <div class="host-meta">${os} · ${openPorts.length} open port(s)</div>
      <div class="host-ports">${openPorts.slice(0, 12).map(p =>
        `<span class="port-chip${p.port === 443 ? ' ssl' : ''}">${p.port}</span>`
      ).join('')}</div>
    `;
    card.addEventListener('click', () => {
      selectedIdx = idx;
      updateHostList(data);
      focusHost(idx);
      updateJsonViewer(host);
    });
    list.appendChild(card);
  });
}

function updateJsonViewer(data) {
  const el = document.getElementById('jsonViewer');
  el.innerHTML = syntaxHighlight(JSON.stringify(data, null, 2));
}

function syntaxHighlight(json) {
  return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+\.?\d*([eE][+\-]?\d+)?)/g, match => {
    let cls = 'num';
    if (/^"/.test(match)) {
      cls = /:$/.test(match) ? 'key' : 'str';
    } else if (/true|false/.test(match)) {
      cls = 'bool';
    } else if (/null/.test(match)) {
      cls = 'null';
    }
    return `<span class="${cls}">${match}</span>`;
  });
}

function focusHost(idx) {
  if (!hostNodes[idx]) return;
  const { mesh } = hostNodes[idx];
  // Animate camera to look at this host
  const target = mesh.position.clone().multiplyScalar(1.5).add(new THREE.Vector3(0, 0, 5));
  camera.position.lerp(target, 0.8);
}

// ── Status indicator ──────────────────────────────────────────────────────────
function setStatus(text, active) {
  document.getElementById('statusText').textContent = text;
  document.getElementById('statusDot').classList.toggle('active', active);
}

// ── Data fetching ─────────────────────────────────────────────────────────────
async function fetchResults() {
  try {
    const res = await fetch('/results');
    const data = await res.json();
    if (JSON.stringify(data) !== JSON.stringify(scanData)) {
      scanData = data;
      buildScene(data);
      updateStats(data);
      updateHostList(data);
      if (!selectedIdx && data.length > 0) {
        updateJsonViewer(data[0]);
      }
      setStatus(data.length ? `${data.length} host(s) loaded` : 'Waiting for data…', !!data.length);
    }
  } catch {
    setStatus('Server unreachable', false);
  }
}

// Start polling
fetchResults();
setInterval(fetchResults, 2000);

// ── Mouse interaction ─────────────────────────────────────────────────────────
canvas.addEventListener('mousemove', e => {
  const rect = canvas.getBoundingClientRect();
  mouse.x =  ((e.clientX - rect.left)  / rect.width)  * 2 - 1;
  mouse.y = -((e.clientY - rect.top)   / rect.height) * 2 + 1;

  tooltip.style.left = (e.clientX - wrap.getBoundingClientRect().left + 14) + 'px';
  tooltip.style.top  = (e.clientY - wrap.getBoundingClientRect().top  + 14) + 'px';
});

canvas.addEventListener('click', () => {
  if (hoveredNode !== null && !hoveredNode.userData?.isPort) {
    const idx = hostNodes.findIndex(n => n.mesh === hoveredNode);
    if (idx >= 0) {
      selectedIdx = idx;
      updateHostList(scanData);
      updateJsonViewer(scanData[idx]);
    }
  }
});

// ── Resize handling ───────────────────────────────────────────────────────────
function resize() {
  const w = wrap.clientWidth, h = wrap.clientHeight;
  renderer.setSize(w, h, false);
  camera.aspect = w / h;
  camera.updateProjectionMatrix();
}
new ResizeObserver(resize).observe(wrap);
resize();

// ── Animation loop ────────────────────────────────────────────────────────────
const clock = new THREE.Clock();
let autoRotate = true;

function animate() {
  requestAnimationFrame(animate);
  const t = clock.getElapsedTime();

  // Hub pulsing
  const pulse = 1 + 0.04 * Math.sin(t * 2.5);
  hub.scale.setScalar(pulse);
  hubRing.rotation.z = t * 0.4;
  hubRing.material.opacity = 0.2 + 0.15 * Math.sin(t * 1.5);
  hub.rotation.y = t * 0.3;

  // Auto-rotate scene
  if (autoRotate) {
    scene.rotation.y = t * 0.05;
  }

  // Orbit host nodes
  hostNodes.forEach((n, i) => {
    n.orbitAngle += 0.0008 + i * 0.00003;
    const x = Math.cos(n.orbitAngle) * n.orbitRadius;
    const z = Math.sin(n.orbitAngle) * n.orbitRadius;
    n.mesh.position.set(x, n.orbitY, z);
    n.mesh.rotation.y = t * 0.5;

    // Update connection line
    if (n.connLine) {
      const pts = [new THREE.Vector3(0,0,0), new THREE.Vector3(x, n.orbitY, z)];
      n.connLine.geometry.setFromPoints(pts);
    }

    // Orbit port satellites
    n.portMeshes.forEach((pm, pi) => {
      const pa = (pi / Math.max(n.portMeshes.length, 1)) * Math.PI * 2 + t * 0.6;
      pm.position.set(x + Math.cos(pa) * 1.5, n.orbitY, z + Math.sin(pa) * 1.5);
    });
  });

  // Raycasting for hover
  raycaster.setFromCamera(mouse, camera);
  const allMeshes = [hub, ...hostNodes.map(n => n.mesh), ...hostNodes.flatMap(n => n.portMeshes)];
  const hits = raycaster.intersectObjects(allMeshes);

  if (hits.length > 0) {
    const obj = hits[0].object;
    hoveredNode = obj;
    canvas.style.cursor = 'pointer';

    if (obj.userData?.isPort) {
      tooltip.style.display = 'block';
      tooltip.textContent = `Port ${obj.userData.port} on ${obj.userData.host}`;
    } else {
      const idx = hostNodes.findIndex(n => n.mesh === obj);
      if (idx >= 0) {
        const h = hostNodes[idx].data;
        const open = (h.ports || []).filter(p => p.state === 'open');
        const fp = open[0]?.fingerprint;
        tooltip.style.display = 'block';
        tooltip.textContent = [
          `Host:    ${h.target}`,
          `OS:      ${fp?.os_guess || 'Unknown'}`,
          `Hops:    ${fp?.hop_distance ?? '?'}`,
          `Virtual: ${fp?.virtualized ? 'Yes 🐳' : 'No'}`,
          `LB:      ${fp?.load_balancer_suspected ? 'Suspected ⚡' : 'No'}`,
          `Open:    ${open.length} port(s)`,
        ].join('\n');
      }
    }
  } else {
    hoveredNode = null;
    canvas.style.cursor = 'default';
    tooltip.style.display = 'none';
  }

  renderer.render(scene, camera);
}
animate();

// ── Button actions ────────────────────────────────────────────────────────────
document.getElementById('btnRefresh').addEventListener('click', fetchResults);

document.getElementById('btnExport').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(scanData, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `netfp-results-${Date.now()}.json`;
  a.click();
});

document.getElementById('btnCopyJson').addEventListener('click', () => {
  navigator.clipboard.writeText(JSON.stringify(scanData, null, 2))
    .then(() => {
      const btn = document.getElementById('btnCopyJson');
      btn.textContent = 'Copied!';
      setTimeout(() => btn.textContent = 'Copy', 1500);
    });
});
