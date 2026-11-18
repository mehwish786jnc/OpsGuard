/* ============================================================================
   OpsGuard — Tech-Noir background particle field (Three.js, vendored).
   3500 cyan points drifting in 3D, easing toward the cursor. Purely
   decorative: if WebGL or the module is unavailable, the #050505 background
   simply shows through.
   ========================================================================== */

const mount = document.getElementById("particles");

function hasWebGL() {
  try {
    const c = document.createElement("canvas");
    return !!(window.WebGLRenderingContext && (c.getContext("webgl") || c.getContext("experimental-webgl")));
  } catch (e) {
    return false;
  }
}

async function init() {
  if (!mount || !hasWebGL()) return;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  let THREE;
  try {
    THREE = await import("three");
  } catch (e) {
    return;
  }

  try {
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 100);
    camera.position.z = 4;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(window.innerWidth, window.innerHeight);
    mount.appendChild(renderer.domElement);

    // 2400 points scattered in a sphere
    const COUNT = 2400;
    const positions = new Float32Array(COUNT * 3);
    for (let i = 0; i < COUNT; i++) {
      const r = 3.2 * Math.cbrt(Math.random());
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      positions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      positions[i * 3 + 2] = r * Math.cos(phi);
    }
    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));

    const mat = new THREE.PointsMaterial({
      color: 0x00f3ff,
      size: 0.017,
      sizeAttenuation: true,
      transparent: true,
      opacity: 0.65,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    const points = new THREE.Points(geo, mat);
    scene.add(points);

    // Cursor easing
    const pointer = { x: 0, y: 0 };
    const target = { x: 0, y: 0 };
    window.addEventListener("mousemove", (e) => {
      pointer.x = (e.clientX / window.innerWidth) * 2 - 1;
      pointer.y = (e.clientY / window.innerHeight) * 2 - 1;
    }, { passive: true });

    const onResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    };
    window.addEventListener("resize", onResize, { passive: true });

    let running = true;
    document.addEventListener("visibilitychange", () => {
      running = !document.hidden;
      renderer.setAnimationLoop(running ? tick : null);
    });

    let last = performance.now();
    function tick() {
      const now = performance.now();
      const dt = Math.min((now - last) / 1000, 0.05);
      last = now;

      target.x += (pointer.x - target.x) * Math.min(1, dt * 1.2);
      target.y += (pointer.y - target.y) * Math.min(1, dt * 1.2);

      points.rotation.y += dt * 0.012 + target.x * dt * 0.08;
      points.rotation.x += target.y * dt * 0.08;
      camera.position.x += (target.x * 0.32 - camera.position.x) * Math.min(1, dt * 0.9);
      camera.position.y += (-target.y * 0.32 - camera.position.y) * Math.min(1, dt * 0.9);
      camera.lookAt(scene.position);

      renderer.render(scene, camera);
    }
    renderer.setAnimationLoop(tick);
  } catch (err) {
    mount.innerHTML = "";
    if (window.console) console.error("particles:", err);
  }
}

init();
