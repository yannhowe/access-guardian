(function () {
  var root = document.getElementById('doc');
  var status = document.getElementById('status');

  function fail(error) {
    var message = error && error.message ? error.message : 'The prep page did not render.';
    if (status) {
      status.textContent = message;
    }
  }

  if (!root) {
    return;
  }

  if (typeof marked === 'undefined' || typeof marked.parse !== 'function') {
    fail(new Error('The markdown script did not load.'));
    return;
  }

  fetch('prep.md').then(function (response) {
    if (!response.ok) {
      throw new Error('prep.md did not load.');
    }
    return response.text();
  }).then(function (markdown) {
    return Promise.resolve(marked.parse(markdown));
  }).then(function (html) {
    if (typeof html !== 'string') {
      throw new Error('The markdown parser did not return HTML.');
    }
    root.innerHTML = html;
  }).catch(fail);
})();
