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
    return mermaid.run({ querySelector: '.mermaid' });
  }

  if (typeof mermaid === 'undefined' || typeof Reveal === 'undefined' || typeof RevealMarkdown === 'undefined') {
    fail(new Error('A slide script did not load.'));
    return;
  }

  mermaid.initialize({ startOnLoad: false, securityLevel: 'strict' });

  Promise.resolve(Reveal.initialize({
    hash: true,
    width: 1200,
    height: 800,
    margin: 0.06,
    plugins: [RevealMarkdown],
  })).then(mountDiagrams).catch(fail);
})();
