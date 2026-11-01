import * as THREE from "three";

/**
 * A captured screen as a surface. Shows a rectangle of a texture (uvRect)
 * with rounded corners, a dim amount, and a defocus amount: a blur done
 * here, per surface, so whatever is in focus stays pixel-sharp. Untoned, so
 * the UI's own colours come through exactly. No decorative light: the only
 * light in the film is the studio's, on the bodies.
 */
export function screenMaterial(map: THREE.Texture, radiusPx = 0, sizePx: [number, number] = [1, 1]) {
  return new THREE.ShaderMaterial({
    transparent: true,
    toneMapped: false,
    depthWrite: false,
    uniforms: {
      map: { value: map },
      uvRect: { value: new THREE.Vector4(0, 0, 1, 1) }, // u0, v0, u1, v1 of the texture shown
      opacity: { value: 1 },
      dim: { value: 0 },
      defocus: { value: 0 }, // 0 sharp … 1 well out of focus
      // A texture-space rect (u0, v0, u1, v1) painted with `fill` instead:
      // the gap a panel slides into. Off by default.
      clipRect: { value: new THREE.Vector4(2, 2, 2, 2) },
      fill: { value: new THREE.Color(0, 0, 0) }, // linear rgb
      radius: { value: radiusPx },
      size: { value: new THREE.Vector2(...sizePx) },
    },
    vertexShader: /* glsl */ `
      varying vec2 vUv;
      void main() { vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }
    `,
    fragmentShader: /* glsl */ `
      uniform sampler2D map; uniform vec4 uvRect, clipRect; uniform float opacity, dim, defocus, radius;
      uniform vec2 size; uniform vec3 fill;
      varying vec2 vUv;
      float rbox(vec2 p, vec2 b, float r) { vec2 q = abs(p) - b + r; return length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - r; }
      void main() {
        vec2 uv = mix(uvRect.xy, uvRect.zw, vUv);
        vec4 c;
        if (defocus <= 0.001) c = texture2D(map, uv);
        else {
          // A 12-tap disc, sampled from blurrier mips as defocus rises.
          vec2 r = defocus * vec2(0.012, 0.012 * (uvRect.z - uvRect.x) / max(uvRect.w - uvRect.y, 1e-4));
          float bias = defocus * 3.0;
          c = texture2D(map, uv, bias) * 0.16;
          for (int i = 0; i < 12; i++) {
            float a = float(i) * 0.5236;
            float rr = (i % 2 == 0) ? 1.0 : 0.55;
            c += texture2D(map, uv + vec2(cos(a), sin(a)) * r * rr, bias) * 0.07;
          }
        }
        if (uv.x > clipRect.x && uv.x < clipRect.z && uv.y > clipRect.y && uv.y < clipRect.w) c = vec4(fill, 1.0);
        // Rounded corners, in pixels of the shown rect.
        vec2 p = (vUv - 0.5) * size;
        float edge = 1.0 - smoothstep(-1.0, 0.5, rbox(p, size * 0.5, radius));
        gl_FragColor = vec4(c.rgb * (1.0 - dim), c.a * opacity * edge);
        #include <colorspace_fragment>
      }
    `,
  });
}
