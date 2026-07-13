#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

"""Variant of generate_architecture_diagram.py that ALSO renders a numbered
legend at the bottom of the image (left + center columns).

Output: ``images/architecture-diagram-with-legend.png``.

Workflow:
    1. Reuse the same Diagram/build steps as the canonical generator to
       produce the base PNG.
    2. Composite a legend area underneath the base PNG using Pillow:
       - left column: steps 1-5
       - center column: steps 6-9
    3. Save the final composed image to its own filename so the original
       ``architecture-diagram.png`` is preserved for direct comparison.

Run from the project root::

    python3 scripts/generate_architecture_diagram_with_legend.py
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from diagrams import Cluster, Diagram, Edge
from diagrams.aws.devtools import Codebuild, Codepipeline, Codestar
from diagrams.aws.management import Cloudformation
from diagrams.aws.security import IAMPermissions, IAMRole
from diagrams.aws.storage import S3
from diagrams.custom import Custom
from diagrams.onprem.vcs import Github


ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "images"
STEP_MARKER_DIR = OUTPUT_DIR / "_step_markers"
BASE_BASENAME = OUTPUT_DIR / "_architecture-diagram-base"
FINAL_PATH = OUTPUT_DIR / "architecture-diagram.png"


# ─────────────────────────────────────────────────────────────────────
# Step descriptions (used both inline by the diagram and by the legend)
# ─────────────────────────────────────────────────────────────────────


STEP_DESCRIPTIONS: list[tuple[int, str]] = [
    (1, "GitHub push aciona o CodeStar Connection."),
    (2, "CodeStar puxa o código para a stage Source do CodePipeline."),
    (3, "Stage Template Validation valida JSONs (PolicyName único, Path, Account IDs)."),
    (4, "Stage Role Validation confirma que a role 'deploy-customer-managed-policy' "
        "está acessível em cada conta-alvo via sts:AssumeRole."),
    (5, "Stage DryRun lê o state em S3 e mostra o diff (sem mutar IAM)."),
    (6, "Approval (manual, opcional): operador revisa o DryRun e aprova/rejeita."),
    (7, "Stage CustomerManagedPolicies executa o deploy efetivo "
        "(grava state em S3 a cada operação bem-sucedida)."),
    (8, "Deploy stage assume a role deploy-customer-managed-policy em cada conta spoke "
        "(1..N contas em paralelo) passando sts:ExternalId."),
    (9, "Em cada conta spoke, a role assumida cria/atualiza/deleta as IAM Customer-Managed "
        "Policies (todas marcadas com tag cx-mng:true). O ciclo se repete em paralelo "
        "para cada conta-alvo da OU."),
]


# ─────────────────────────────────────────────────────────────────────
# Numbered step markers (light-gray spheres with the number inside)
# ─────────────────────────────────────────────────────────────────────


_FONT_CANDIDATES = [
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
]
_FONT_CANDIDATES_REGULAR = [
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
]


def _load_font(size: int, bold: bool = True):
    candidates = _FONT_CANDIDATES if bold else _FONT_CANDIDATES_REGULAR
    for path in candidates:
        try:
            return ImageFont.truetype(path, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def _make_step_marker(n: int, size: int = 70) -> Path:
    STEP_MARKER_DIR.mkdir(parents=True, exist_ok=True)
    out = STEP_MARKER_DIR / f"step_{n}.png"
    if out.exists():
        return out

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    margin = 4
    draw.ellipse(
        [margin, margin, size - margin - 1, size - margin - 1],
        fill="#e8e8e8",
        outline="#1f1f1f",
        width=4,
    )
    font = _load_font(size=int(size * 0.55))
    label = str(n)
    bbox = draw.textbbox((0, 0), label, font=font)
    w = bbox[2] - bbox[0]
    h = bbox[3] - bbox[1]
    draw.text(
        ((size - w) / 2 - bbox[0], (size - h) / 2 - bbox[1] - size * 0.02),
        label,
        fill="#1f1f1f",
        font=font,
    )
    img.save(out)
    return out


def _step(n: int) -> Custom:
    return Custom("", str(_make_step_marker(n)))


# ─────────────────────────────────────────────────────────────────────
# Diagram
# ─────────────────────────────────────────────────────────────────────


solid = Edge(color="#3b3b3b")
dashed = Edge(color="#8a8a8a", style="dashed")


def build_base_diagram():
    """Generate the base architecture diagram (without legend)."""
    OUTPUT_DIR.mkdir(exist_ok=True)

    graph_attr = {
        "fontsize": "16",
        "bgcolor": "white",
        "pad": "0.4",
        "splines": "spline",
        "nodesep": "0.4",
        "ranksep": "0.8",
        "compound": "true",
    }

    with Diagram(
        "IAM Customer Managed Policies Pipeline",
        filename=str(BASE_BASENAME),
        outformat="png",
        show=False,
        direction="LR",
        graph_attr=graph_attr,
    ):
        github = Github("GitHub Repository")
        codestar = Codestar("CodeStar\nConnection")
        github >> _step(1) >> codestar

        with Cluster("Pipeline Account (cx-mng-pipeline)"):
            with Cluster("Pipeline Stages"):
                source = Codepipeline("Source")
                tpl_validation = Codebuild("Template\nValidation")
                role_validation = Codebuild("Role\nValidation")
                dry_run = Codebuild("DryRun")
                approval = Codebuild("Approval\n(manual,\noptional)")
                deploy = Codebuild("Customer\nManaged\nPolicies")

                source >> _step(3) >> tpl_validation
                tpl_validation >> _step(4) >> role_validation
                role_validation >> _step(5) >> dry_run
                dry_run >> _step(6) >> approval
                approval >> _step(7) >> deploy

        # Bucket de artefatos / state — fora do cluster Pipeline Account
        # para o cluster do pipeline ficar mais estreito e não empurrar o
        # cluster spoke para a linha de baixo. constraint=false evita que
        # esta edge "puxe" o bucket para a row do deploy, deixando-o livre
        # para o engine posicioná-lo abaixo.
        artifact_bucket = S3("Artifact Bucket\n+ State (SSE-KMS)")
        deploy >> Edge(
            label="state I/O\n(DryRun lê,\nCustomerManagedPolicies lê e escreve)",
            style="dashed",
            color="#8a8a8a",
            fontsize="11",
            constraint="false",
        ) >> artifact_bucket

        codestar >> _step(2) >> source

        # ── StackSet (fora do cluster spoke para o cluster spoke ficar
        # compacto horizontalmente e alinhar com o pipeline na mesma row).
        stackset = Cloudformation("StackSet\ncx-mng-stackset-\ndeploy-role")

        with Cluster("Spoke (target) AWS Accounts — StackSet auto-deploy on OU"):
            iam_action_label = (
                "iam:CreatePolicy\n"
                "iam:CreatePolicyVersion\n"
                "iam:DeletePolicy*\n"
                "iam:TagPolicy"
            )

            with Cluster("Account 1..N\n(em cada conta da OU)"):
                target_role = IAMRole("deploy-customer-\nmanaged-policy")
                managed_policies = IAMPermissions(
                    "IAM Customer-Managed\nPolicies\n(tag cx-mng:true)"
                )
                target_role >> _step(9) >> Edge(
                    label=iam_action_label,
                    color="#b85450",
                    fontsize="10",
                ) >> managed_policies

        # StackSet → role (não influencia o rank principal).
        stackset >> Edge(
            label="cria a role\n(auto-deploy em cada conta)",
            color="#8a8a8a",
            style="dashed",
            constraint="false",
        ) >> target_role

        # Step 8: deploy → AssumeRole na role spoke (executado em cada conta-alvo).
        deploy >> _step(8) >> Edge(
            label="sts:AssumeRole + ExternalId\n(em cada conta-alvo)",
            color="#b85450",
            fontsize="13",
        ) >> target_role


# ─────────────────────────────────────────────────────────────────────
# Legend rendering — adds a numbered list of step descriptions below
# the base diagram, in two columns (left + center).
# ─────────────────────────────────────────────────────────────────────


def _wrap_text(draw, text: str, font, max_width: int) -> list[str]:
    """Greedy line wrap for ``text`` so each line fits within ``max_width`` px."""
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    for word in words:
        candidate = " ".join(current + [word])
        bbox = draw.textbbox((0, 0), candidate, font=font)
        if bbox[2] - bbox[0] <= max_width:
            current.append(word)
        else:
            if current:
                lines.append(" ".join(current))
            current = [word]
    if current:
        lines.append(" ".join(current))
    return lines


def _draw_legend_column(draw, items, x, y, *, marker_size, padding,
                         line_height, font_step, font_text, max_text_width):
    """Draw a column of (number-sphere + multiline description) entries.

    Returns the y coordinate just below the last drawn item.
    """
    cursor_y = y
    for n, description in items:
        # Number sphere on the left.
        marker_path = _make_step_marker(n, size=marker_size)
        marker = Image.open(marker_path).convert("RGBA")
        draw._image.paste(marker, (x, cursor_y), marker)

        # Description text to the right of the marker, wrapped.
        text_x = x + marker_size + 14
        text_y = cursor_y + 6
        lines = _wrap_text(draw, description, font_text, max_text_width)
        for line in lines:
            draw.text((text_x, text_y), line, fill="#1f1f1f", font=font_text)
            text_y += line_height

        # Move cursor past the taller of marker/text.
        block_h = max(marker_size, len(lines) * line_height + 12)
        cursor_y += block_h + padding

    return cursor_y


def compose_with_legend():
    """Open the base diagram, paint a legend below it, save the final PNG."""
    base_path = BASE_BASENAME.with_suffix(".png")
    base = Image.open(base_path).convert("RGBA")
    base_w, base_h = base.size

    # Legend layout
    marker_size = 56
    padding = 14
    line_height = 22
    column_gap = 80
    margin_x = 60
    margin_top = 30
    margin_bottom = 50

    # Two columns: left = 1..5, center = 6..9
    left_items = [(n, desc) for n, desc in STEP_DESCRIPTIONS if n <= 5]
    right_items = [(n, desc) for n, desc in STEP_DESCRIPTIONS if n > 5]

    column_width = (base_w - 2 * margin_x - column_gap) // 2
    text_max_width = column_width - marker_size - 14

    # Pre-render fonts
    font_title = _load_font(size=28, bold=True)
    font_step = _load_font(size=20, bold=True)
    font_text = _load_font(size=18, bold=False)

    # Estimate legend height by simulating the wrap on a temp image.
    tmp_img = Image.new("RGBA", (base_w, 100), (255, 255, 255, 0))
    tmp_draw = ImageDraw.Draw(tmp_img)

    def column_height(items):
        h = 0
        for _, desc in items:
            lines = _wrap_text(tmp_draw, desc, font_text, text_max_width)
            block_h = max(marker_size, len(lines) * line_height + 12)
            h += block_h + padding
        return h

    legend_inner_h = max(column_height(left_items), column_height(right_items))
    legend_h = margin_top + 50 + legend_inner_h + margin_bottom  # +50 for title

    # Build the final canvas: base on top, legend below.
    final = Image.new("RGBA", (base_w, base_h + legend_h), (255, 255, 255, 255))
    final.paste(base, (0, 0), base)

    draw = ImageDraw.Draw(final)
    # Light separator line between diagram and legend.
    draw.line(
        [(margin_x, base_h + 6), (base_w - margin_x, base_h + 6)],
        fill="#cccccc",
        width=2,
    )

    # Legend title
    title = "Etapas do fluxo (passo a passo)"
    draw.text((margin_x, base_h + margin_top), title, fill="#1f1f1f", font=font_title)

    legend_top = base_h + margin_top + 50

    # Left column (steps 1-5)
    _draw_legend_column(
        draw, left_items,
        x=margin_x,
        y=legend_top,
        marker_size=marker_size,
        padding=padding,
        line_height=line_height,
        font_step=font_step,
        font_text=font_text,
        max_text_width=text_max_width,
    )
    # Right column (steps 6-9), starting in the center
    _draw_legend_column(
        draw, right_items,
        x=margin_x + column_width + column_gap,
        y=legend_top,
        marker_size=marker_size,
        padding=padding,
        line_height=line_height,
        font_step=font_step,
        font_text=font_text,
        max_text_width=text_max_width,
    )

    final.save(FINAL_PATH)
    # Clean up the intermediate base file
    try:
        base_path.unlink()
    except FileNotFoundError:
        pass


def main() -> int:
    try:
        build_base_diagram()
        compose_with_legend()
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {exc}")
        return 1
    print(f"Wrote {FINAL_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
