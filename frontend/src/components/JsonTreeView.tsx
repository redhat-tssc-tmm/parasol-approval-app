import React, { useState } from 'react';

interface JsonTreeViewProps {
  data: unknown;
  defaultExpanded?: boolean;
}

interface NodeProps {
  keyName?: string;
  value: unknown;
  depth: number;
  defaultExpanded: boolean;
  isLast: boolean;
}

function isPlaceholder(val: string): boolean {
  return val.startsWith('<base64 data,') && val.endsWith('>');
}

function JsonNode({ keyName, value, depth, defaultExpanded, isLast }: NodeProps) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const indent = depth * 20;
  const comma = isLast ? '' : ',';

  if (value === null) {
    return (
      <div style={{ paddingLeft: indent }} className="json-line">
        {keyName !== undefined && <span className="json-key">"{keyName}"</span>}
        {keyName !== undefined && <span className="json-punct">: </span>}
        <span className="json-null">null</span>
        <span className="json-punct">{comma}</span>
      </div>
    );
  }

  if (typeof value === 'boolean') {
    return (
      <div style={{ paddingLeft: indent }} className="json-line">
        {keyName !== undefined && <span className="json-key">"{keyName}"</span>}
        {keyName !== undefined && <span className="json-punct">: </span>}
        <span className="json-bool">{String(value)}</span>
        <span className="json-punct">{comma}</span>
      </div>
    );
  }

  if (typeof value === 'number') {
    return (
      <div style={{ paddingLeft: indent }} className="json-line">
        {keyName !== undefined && <span className="json-key">"{keyName}"</span>}
        {keyName !== undefined && <span className="json-punct">: </span>}
        <span className="json-number">{String(value)}</span>
        <span className="json-punct">{comma}</span>
      </div>
    );
  }

  if (typeof value === 'string') {
    const displayVal = value.length > 120 ? value.slice(0, 120) + '...' : value;
    const className = isPlaceholder(value) ? 'json-placeholder' : 'json-string';
    return (
      <div style={{ paddingLeft: indent }} className="json-line">
        {keyName !== undefined && <span className="json-key">"{keyName}"</span>}
        {keyName !== undefined && <span className="json-punct">: </span>}
        <span className={className}>"{displayVal}"</span>
        <span className="json-punct">{comma}</span>
      </div>
    );
  }

  if (Array.isArray(value)) {
    const items = value;
    if (items.length === 0) {
      return (
        <div style={{ paddingLeft: indent }} className="json-line">
          {keyName !== undefined && <span className="json-key">"{keyName}"</span>}
          {keyName !== undefined && <span className="json-punct">: </span>}
          <span className="json-punct">[]</span>
          <span className="json-punct">{comma}</span>
        </div>
      );
    }

    return (
      <div>
        <div
          style={{ paddingLeft: indent, cursor: 'pointer' }}
          className="json-line json-expandable"
          onClick={() => setExpanded(!expanded)}
        >
          <span className="json-toggle">{expanded ? '▾' : '▸'} </span>
          {keyName !== undefined && <span className="json-key">"{keyName}"</span>}
          {keyName !== undefined && <span className="json-punct">: </span>}
          {expanded ? (
            <span className="json-punct">[</span>
          ) : (
            <>
              <span className="json-punct">[</span>
              <span className="json-collapsed"> {items.length} {items.length === 1 ? 'item' : 'items'} </span>
              <span className="json-punct">]</span>
              <span className="json-punct">{comma}</span>
            </>
          )}
        </div>
        {expanded && (
          <>
            {items.map((item, i) => (
              <JsonNode
                key={i}
                value={item}
                depth={depth + 1}
                defaultExpanded={false}
                isLast={i === items.length - 1}
              />
            ))}
            <div style={{ paddingLeft: indent }} className="json-line">
              <span className="json-punct">]</span>
              <span className="json-punct">{comma}</span>
            </div>
          </>
        )}
      </div>
    );
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) {
      return (
        <div style={{ paddingLeft: indent }} className="json-line">
          {keyName !== undefined && <span className="json-key">"{keyName}"</span>}
          {keyName !== undefined && <span className="json-punct">: </span>}
          <span className="json-punct">{'{}'}</span>
          <span className="json-punct">{comma}</span>
        </div>
      );
    }

    return (
      <div>
        <div
          style={{ paddingLeft: indent, cursor: 'pointer' }}
          className="json-line json-expandable"
          onClick={() => setExpanded(!expanded)}
        >
          <span className="json-toggle">{expanded ? '▾' : '▸'} </span>
          {keyName !== undefined && <span className="json-key">"{keyName}"</span>}
          {keyName !== undefined && <span className="json-punct">: </span>}
          {expanded ? (
            <span className="json-punct">{'{'}</span>
          ) : (
            <>
              <span className="json-punct">{'{'}</span>
              <span className="json-collapsed"> {entries.length} {entries.length === 1 ? 'key' : 'keys'} </span>
              <span className="json-punct">{'}'}</span>
              <span className="json-punct">{comma}</span>
            </>
          )}
        </div>
        {expanded && (
          <>
            {entries.map(([k, v], i) => (
              <JsonNode
                key={k}
                keyName={k}
                value={v}
                depth={depth + 1}
                defaultExpanded={false}
                isLast={i === entries.length - 1}
              />
            ))}
            <div style={{ paddingLeft: indent }} className="json-line">
              <span className="json-punct">{'}'}</span>
              <span className="json-punct">{comma}</span>
            </div>
          </>
        )}
      </div>
    );
  }

  return null;
}

export const JsonTreeView: React.FC<JsonTreeViewProps> = ({ data, defaultExpanded = false }) => {
  return (
    <div className="json-tree">
      <style>{`
        .json-tree {
          font-family: var(--pf-t--global--font--family--mono);
          font-size: 0.85rem;
          line-height: 1.6;
          overflow-x: auto;
        }
        .json-line {
          white-space: nowrap;
          padding: 1px 0;
        }
        .json-line:hover {
          background: rgba(128,128,128,0.15);
        }
        .json-expandable {
          user-select: none;
        }
        .json-toggle {
          display: inline-block;
          width: 1em;
        }

        /* Dark mode (default) */
        .pf-v6-theme-dark .json-key { color: #9cdcfe; }
        .pf-v6-theme-dark .json-string { color: #ce9178; }
        .pf-v6-theme-dark .json-number { color: #b5cea8; }
        .pf-v6-theme-dark .json-bool { color: #569cd6; }
        .pf-v6-theme-dark .json-null { color: #808080; font-style: italic; }
        .pf-v6-theme-dark .json-punct { color: #cccccc; }
        .pf-v6-theme-dark .json-toggle { color: #cccccc; }
        .pf-v6-theme-dark .json-collapsed { color: #b0b0b0; font-style: italic; font-size: 0.8em; }
        .pf-v6-theme-dark .json-placeholder { color: #808080; font-style: italic; }

        /* Light mode */
        .json-key { color: #0451a5; }
        .json-string { color: #a31515; }
        .json-number { color: #098658; }
        .json-bool { color: #0000ff; }
        .json-null { color: #666666; font-style: italic; }
        .json-punct { color: #333333; }
        .json-toggle { color: #333333; }
        .json-collapsed { color: #666666; font-style: italic; font-size: 0.8em; }
        .json-placeholder { color: #666666; font-style: italic; }
      `}</style>
      <JsonNode value={data} depth={0} defaultExpanded={defaultExpanded} isLast={true} />
    </div>
  );
};
