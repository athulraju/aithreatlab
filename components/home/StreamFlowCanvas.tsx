"use client";

import { useEffect, useRef } from "react";
import styles from "./HomeExperience.module.css";

const ARTWORK = { width: 1585, height: 992 };
const BASE_SRC = "/images/living-intelligence-hero-v2.png";
const FLOW_SRC = "/images/stream-flow-map.png";

// This does not draw anything on top of the artwork. It renders the artwork itself
// through a WebGL flow-map shader: a mask+direction texture (derived from the actual
// pixels of living-intelligence-hero-v2.png — see stream-flow-map.png) tells the
// fragment shader which pixels belong to the green/gold streams and which way each
// one flows. Inside that mask the shader samples the SAME artwork texture at a
// UV coordinate slid along the stream's own direction, using the standard two-phase
// flow-map blend so the slide never visibly resets. Outside the mask (the landscape,
// rock, panels-backdrop) the shader samples the artwork at its true position, so
// nothing but the rivers of light moves.
const VERTEX_SRC = `#version 300 es
in vec2 a_pos;
out vec2 v_uv;
void main() {
  v_uv = a_pos * 0.5 + 0.5;
  gl_Position = vec4(a_pos, 0.0, 1.0);
}`;

const FRAGMENT_SRC = `#version 300 es
precision highp float;
in vec2 v_uv;
out vec4 outColor;

uniform sampler2D u_base;
uniform sampler2D u_flow;
uniform vec2 u_canvasSize;
uniform vec2 u_imageSize;
uniform float u_positionX;
uniform float u_time;
uniform float u_flowScale;
uniform float u_intensity;

vec2 coverUv(vec2 fragUv) {
  vec2 canvasPx = fragUv * u_canvasSize;
  float scale = max(u_canvasSize.x / u_imageSize.x, u_canvasSize.y / u_imageSize.y);
  vec2 renderedSize = u_imageSize * scale;
  float offsetX = (u_canvasSize.x - renderedSize.x) * u_positionX;
  float offsetY = (u_canvasSize.y - renderedSize.y) * 0.5;
  return (canvasPx - vec2(offsetX, offsetY)) / renderedSize;
}

void main() {
  vec2 uv = coverUv(v_uv);
  if (uv.x < 0.0 || uv.x > 1.0 || uv.y < 0.0 || uv.y > 1.0) {
    outColor = vec4(0.0);
    return;
  }

  vec4 flowSample = texture(u_flow, uv);
  float greenMask = flowSample.r;
  float goldMask = flowSample.g;
  float mask = max(greenMask, goldMask);
  vec2 flowDir = (flowSample.ba * 2.0 - 1.0) * 1.5;

  vec3 baseColor = texture(u_base, uv).rgb;

  if (mask < 0.02) {
    outColor = vec4(baseColor, 1.0);
    return;
  }

  float phaseA = fract(u_time);
  float phaseB = fract(u_time + 0.5);
  float weightA = 1.0 - abs(phaseA * 2.0 - 1.0);
  float weightB = 1.0 - weightA;

  vec2 uvA = uv - flowDir * u_flowScale * phaseA;
  vec2 uvB = uv - flowDir * u_flowScale * phaseB;
  vec3 colorA = texture(u_base, clamp(uvA, 0.0, 1.0)).rgb;
  vec3 colorB = texture(u_base, clamp(uvB, 0.0, 1.0)).rgb;
  vec3 flowColor = colorA * weightA + colorB * weightB;

  // Moving shimmer confined to the stream mask: a slow traveling brightness ripple
  // riding along the flow direction, independent of the base-texture displacement.
  float ripple = sin(dot(uv, normalize(flowDir + 1e-4)) * 90.0 - u_time * 5.2);
  float shimmer = 1.0 + 0.16 * mask * ripple;

  vec3 result = mix(baseColor, flowColor * shimmer, mask * u_intensity);
  outColor = vec4(result, 1.0);
}`;

function compileShader(gl: WebGL2RenderingContext, type: number, source: string) {
  const shader = gl.createShader(type);
  if (!shader) return null;
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    gl.deleteShader(shader);
    return null;
  }
  return shader;
}

function loadTexture(gl: WebGL2RenderingContext, src: string): Promise<WebGLTexture> {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.crossOrigin = "anonymous";
    image.onload = () => {
      const texture = gl.createTexture();
      if (!texture) return reject(new Error("texture alloc failed"));
      gl.bindTexture(gl.TEXTURE_2D, texture);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, image);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
      resolve(texture);
    };
    image.onerror = reject;
    image.src = src;
  });
}

export function StreamFlowCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const gl = canvas.getContext("webgl2", { alpha: true, antialias: false, premultipliedAlpha: true });
    if (!gl) return;

    const vertexShader = compileShader(gl, gl.VERTEX_SHADER, VERTEX_SRC);
    const fragmentShader = compileShader(gl, gl.FRAGMENT_SHADER, FRAGMENT_SRC);
    if (!vertexShader || !fragmentShader) return;

    const program = gl.createProgram();
    if (!program) return;
    gl.attachShader(program, vertexShader);
    gl.attachShader(program, fragmentShader);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) return;
    gl.useProgram(program);

    const quad = new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]);
    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, quad, gl.STATIC_DRAW);
    const posLoc = gl.getAttribLocation(program, "a_pos");
    gl.enableVertexAttribArray(posLoc);
    gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0);

    const uniforms = {
      base: gl.getUniformLocation(program, "u_base"),
      flow: gl.getUniformLocation(program, "u_flow"),
      canvasSize: gl.getUniformLocation(program, "u_canvasSize"),
      imageSize: gl.getUniformLocation(program, "u_imageSize"),
      positionX: gl.getUniformLocation(program, "u_positionX"),
      time: gl.getUniformLocation(program, "u_time"),
      flowScale: gl.getUniformLocation(program, "u_flowScale"),
      intensity: gl.getUniformLocation(program, "u_intensity"),
    };

    const mobile = window.innerWidth <= 760;
    let width = 0, height = 0, dpr = 1, frame = 0, elapsed = 0, previous = performance.now();
    let visible = !document.hidden;
    let ready = false;

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      width = rect.width; height = rect.height;
      dpr = Math.min(window.devicePixelRatio || 1, mobile ? 1.5 : 2);
      canvas.width = Math.max(1, Math.round(width * dpr));
      canvas.height = Math.max(1, Math.round(height * dpr));
      gl.viewport(0, 0, canvas.width, canvas.height);
    };

    const render = (now: number) => {
      if (!visible || !ready) return;
      const delta = Math.min(40, now - previous) / 1000;
      previous = now;
      elapsed += delta;

      gl.uniform1f(uniforms.time, elapsed * 0.09);
      gl.uniform2f(uniforms.canvasSize, width, height);
      gl.uniform2f(uniforms.imageSize, ARTWORK.width, ARTWORK.height);
      gl.uniform1f(uniforms.positionX, window.innerWidth <= 760 ? 0.66 : 0.5);
      gl.uniform1f(uniforms.flowScale, mobile ? 0.014 : 0.02);
      gl.uniform1f(uniforms.intensity, 0.92);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);

      frame = requestAnimationFrame(render);
    };

    const observer = new ResizeObserver(resize);
    observer.observe(canvas);
    resize();

    let cancelled = false;
    Promise.all([loadTexture(gl, BASE_SRC), loadTexture(gl, FLOW_SRC)]).then(([baseTex, flowTex]) => {
      if (cancelled) return;
      gl.activeTexture(gl.TEXTURE0);
      gl.bindTexture(gl.TEXTURE_2D, baseTex);
      gl.uniform1i(uniforms.base, 0);
      gl.activeTexture(gl.TEXTURE1);
      gl.bindTexture(gl.TEXTURE_2D, flowTex);
      gl.uniform1i(uniforms.flow, 1);
      ready = true;
      previous = performance.now();
      frame = requestAnimationFrame(render);
    }).catch(() => {
      // Texture failed to load (e.g. asset missing); leave the static CSS
      // background-image as the fallback instead of throwing.
    });

    const onVisibility = () => {
      visible = !document.hidden;
      if (visible) { previous = performance.now(); cancelAnimationFrame(frame); frame = requestAnimationFrame(render); }
      else cancelAnimationFrame(frame);
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      cancelled = true;
      cancelAnimationFrame(frame);
      observer.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
      gl.deleteProgram(program);
      gl.deleteShader(vertexShader);
      gl.deleteShader(fragmentShader);
      gl.deleteBuffer(buffer);
    };
  }, []);

  return <canvas ref={canvasRef} className={styles.streamCanvas} aria-hidden="true" />;
}
