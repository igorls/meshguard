<script setup>
import { onMounted, ref } from "vue";
import { useData } from "vitepress";

const { isDark } = useData();
const canvasRef = ref(null);
const terminalVisible = ref(false);

// Animated mesh network canvas
onMounted(() => {
  const canvas = canvasRef.value;
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  let animId;
  let nodes = [];
  const NODE_COUNT = 40;
  const CONNECTION_DIST = 150;

  function resize() {
    canvas.width = canvas.offsetWidth * window.devicePixelRatio;
    canvas.height = canvas.offsetHeight * window.devicePixelRatio;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
  }

  function initNodes() {
    const w = canvas.offsetWidth;
    const h = canvas.offsetHeight;
    nodes = Array.from({ length: NODE_COUNT }, () => ({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      radius: Math.random() * 2 + 1,
    }));
  }

  function draw() {
    const w = canvas.offsetWidth;
    const h = canvas.offsetHeight;
    ctx.clearRect(0, 0, w, h);

    // Update positions
    for (const node of nodes) {
      node.x += node.vx;
      node.y += node.vy;
      if (node.x < 0 || node.x > w) node.vx *= -1;
      if (node.y < 0 || node.y > h) node.vy *= -1;
    }

    // Draw connections
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONNECTION_DIST) {
          const alpha = (1 - dist / CONNECTION_DIST) * 0.3;
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.strokeStyle = `rgba(0, 255, 136, ${alpha})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }

    // Draw nodes
    for (const node of nodes) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(0, 255, 136, 0.6)";
      ctx.fill();
    }

    animId = requestAnimationFrame(draw);
  }

  resize();
  initNodes();
  draw();

  window.addEventListener("resize", () => {
    cancelAnimationFrame(animId);
    resize();
    initNodes();
    draw();
  });

  // Trigger terminal animation
  setTimeout(() => {
    terminalVisible.value = true;
  }, 500);
});

const terminalLines = [
  { type: "comment", text: "# install meshguard" },
  {
    type: "command",
    text: "curl -fsSL https://raw.githubusercontent.com/igorls/meshguard/main/install.sh | bash",
  },
  { type: "output", text: "✓ meshguard 0.3.1" },
  { type: "blank" },
  { type: "comment", text: "# generate identity & join the mesh" },
  { type: "command", text: "meshguard keygen" },
  { type: "output", text: "Identity keypair generated." },
  { type: "command", text: "sudo meshguard up --seed 1.2.3.4:51821" },
  { type: "output", text: "meshguard starting..." },
  { type: "highlight", text: "  mesh IP: 10.99.189.145" },
  {
    type: "highlight",
    text: "  public endpoint: 203.0.113.42:8591 (behind NAT, cone)",
  },
  { type: "output", text: "  peer joined: 10.99.42.17 [handshake sent]" },
];

const features = [
  {
    label: "// trust",
    title: "Serverless & Trustless",
    desc: "No control plane, no coordinator. Each node holds its own Ed25519 identity. The mesh is self-organizing.",
  },
  {
    label: "// discovery",
    title: "SWIM Gossip",
    desc: "O(log N) convergence with failure detection. Membership propagates in seconds via epidemic protocol.",
  },
  {
    label: "// crypto",
    title: "WireGuard Tunnels",
    desc: "Noise_IKpsk2 handshake, end-to-end encryption. Kernel or userspace mode with zero-copy data plane.",
  },
  {
    label: "// nat",
    title: "NAT Traversal",
    desc: "STUN discovery, UDP hole punching, relay fallback. Works behind cone and symmetric NATs.",
  },
  {
    label: "// identity",
    title: "Deterministic IPs",
    desc: "Mesh IP derived from Ed25519 public key via Blake3. No DHCP, no conflicts, no coordination needed.",
  },
  {
    label: "// perf",
    title: "Zero Overhead",
    desc: "Built in Zig. Single static binary, io_uring event loop, multi-queue TUN, GSO/GRO offloads.",
  },
];
</script>

<template>
  <div class="custom-home">
    <!-- Hero -->
    <section class="hero-section">
      <canvas ref="canvasRef" class="hero-canvas" />
      <div class="hero-content">
        <div class="hero-badge">
          <span class="dot" />
          v0.3.1 · MIT License · Linux
        </div>
        <h1 class="hero-title">meshguard</h1>
        <p class="hero-tagline">
          Decentralized WireGuard mesh VPN.<br />
          Zero central authority. Trust-agnostic.<br />
          Single static binary.
        </p>
        <div class="hero-actions">
          <a href="/meshguard/guide/getting-started" class="btn-primary"
            >$ install</a
          >
          <a href="/meshguard/concepts/architecture" class="btn-secondary"
            >architecture →</a
          >
          <a
            href="https://github.com/igorls/meshguard"
            class="btn-secondary"
            target="_blank"
            >github ↗</a
          >
        </div>
      </div>
    </section>

    <!-- Terminal demo -->
    <section class="terminal-section" v-if="terminalVisible">
      <div class="terminal">
        <div class="terminal-header">
          <span class="terminal-dot red" />
          <span class="terminal-dot yellow" />
          <span class="terminal-dot green" />
          <span class="terminal-title">meshguard — bash</span>
        </div>
        <div class="terminal-body">
          <span
            v-for="(line, i) in terminalLines"
            :key="i"
            class="terminal-line"
            :style="{ animationDelay: `${i * 0.15}s` }"
          >
            <template v-if="line.type === 'command'">
              <span class="prompt">$ </span>{{ line.text }}
            </template>
            <template v-else-if="line.type === 'comment'">
              <span class="comment">{{ line.text }}</span>
            </template>
            <template v-else-if="line.type === 'highlight'">
              <span class="highlight">{{ line.text }}</span>
            </template>
            <template v-else-if="line.type === 'output'">
              <span class="output">{{ line.text }}</span>
            </template>
            <template v-else><br /></template>
          </span>
        </div>
      </div>
    </section>

    <!-- Features -->
    <section class="features-section">
      <div class="features-header">
        <h2>// how it works</h2>
      </div>
      <div class="features-grid">
        <div v-for="f in features" :key="f.title" class="feature-card">
          <div class="feature-icon">{{ f.label }}</div>
          <h3>{{ f.title }}</h3>
          <p>{{ f.desc }}</p>
        </div>
      </div>
    </section>

    <!-- Stats -->
    <section class="stats-section">
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value">4.8+</div>
          <div class="stat-label">Gbps throughput</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">~6k</div>
          <div class="stat-label">Lines of Zig</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">0</div>
          <div class="stat-label">Dependencies</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">1</div>
          <div class="stat-label">Binary</div>
        </div>
      </div>
    </section>

    <!-- Footer -->
    <footer class="custom-footer">
      <p>
        Released under the
        <a href="https://opensource.org/licenses/MIT">MIT License</a>
      </p>
      <p>Built with Zig · Powered by WireGuard</p>
    </footer>
  </div>
</template>
