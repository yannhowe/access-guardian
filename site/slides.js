(function () {
  var status = document.getElementById('status');

  function fail(error) {
    var message = error && error.message ? error.message : 'The slides did not start.';
    if (status) {
      status.textContent = message;
    }
  }

  function mountDiagrams() {
    var blocks = document.querySelectorAll('code.mermaid, code.language-mermaid');
    for (var i = 0; i < blocks.length; i++) {
      var code = blocks[i];
      var pre = code.parentElement;
      var diagram = document.createElement('div');
      diagram.className = 'mermaid';
      diagram.textContent = code.textContent;
      if (pre && pre.parentNode) {
        pre.parentNode.replaceChild(diagram, pre);
      }
    }
    var saved = [];
    var diagrams = document.querySelectorAll('.mermaid');
    for (var j = 0; j < diagrams.length; j++) {
      var section = diagrams[j].closest('section');
      if (!section) {
        continue;
      }
      saved.push({
        section: section,
        hidden: section.hasAttribute('hidden'),
        display: section.style.display,
      });
      section.removeAttribute('hidden');
      section.style.display = 'block';
    }

    function restoreSections() {
      for (var k = 0; k < saved.length; k++) {
        if (saved[k].hidden) {
          saved[k].section.setAttribute('hidden', '');
        }
        saved[k].section.style.display = saved[k].display;
      }
    }

    var fonts = document.fonts && document.fonts.ready ? document.fonts.ready : Promise.resolve();
    return fonts.then(function () {
      return mermaid.run({ querySelector: '.mermaid' });
    }).then(loosenLabels).then(restoreSections, function (error) {
      restoreSections();
      throw error;
    });
  }

  // The label box mermaid writes is a few pixels narrower than the text.
  // Widen it so the last letters stay visible.
  function loosenLabels() {
    var boxes = document.querySelectorAll('.mermaid foreignObject');
    for (var i = 0; i < boxes.length; i++) {
      var fo = boxes[i];
      var width = parseFloat(fo.getAttribute('width'));
      if (!width || width <= 0) {
        continue;
      }
      var extra = 32;
      fo.setAttribute('width', String(width + extra));
      var group = fo.parentNode;
      if (!group || typeof group.getAttribute !== 'function') {
        continue;
      }
      var transform = group.getAttribute('transform') || '';
      var match = /translate\(\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)\s*\)/.exec(transform);
      if (!match) {
        continue;
      }
      var x = parseFloat(match[1]) - extra / 2;
      group.setAttribute('transform', 'translate(' + x + ', ' + match[2] + ')');
    }
  }

  if (typeof mermaid === 'undefined' || typeof Reveal === 'undefined' || typeof RevealMarkdown === 'undefined') {
    fail(new Error('A slide script did not load.'));
    return;
  }

  mermaid.initialize({
    startOnLoad: false,
    securityLevel: 'strict',
    flowchart: {
      htmlLabels: true,
      wrappingWidth: 150,
      padding: 10,
      nodeSpacing: 18,
      rankSpacing: 22,
      useMaxWidth: true,
    },
  });

  Promise.resolve(Reveal.initialize({
    hash: true,
    width: 1200,
    height: 800,
    margin: 0.06,
    plugins: [RevealMarkdown],
  })).then(mountDiagrams).catch(fail);
})();
