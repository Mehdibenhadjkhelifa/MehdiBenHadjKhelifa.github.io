/* Adapted from https://benfrain.com/building-a-table-of-contents-with-active-indicator-using-javascript-intersection-observers/ */

window.onload = () => {
    const links = [...document.querySelectorAll('.toc a')];
    const hashes = links.map(link => "#" + link.getAttribute("href").split("#")[1]);
    const sections = links.map(link => document.querySelector("#" + link.getAttribute("href").split("#")[1]));
  
    function didThisIntersectionHappenAtTop(i) {
      return i.rootBounds.bottom - i.boundingClientRect.bottom > i.rootBounds.bottom / 2 ? true
      : false;
    }
  
    function getPriorHeading(i) {
      let priorEle = (ele) => ele === i.target;
      return sections.findIndex(priorEle);
    }
  
    const options = {
      root: null,
      // don't set both top and bottom, that makes it unreliable
      rootMargin: "0px 0px -50% 0px",
      threshold: 1,
    };
  
    var observeHtags = new IntersectionObserver(setCurrent, options);
  
    // align
    let toc = document.getElementsByClassName("toc")[0];
  
    // highlight first one if visible
    if (sections.length >= 1 && sections[0].getBoundingClientRect().top + window.scrollY < (window.innerHeight / 2)) {
      links.forEach(link => link.classList.remove("active"));
      links[0].classList.add("active");
    }
  
    // if we have a hash highlight that initially instead of basing on visible
    if (hashes.includes(location.hash)) {
      links.forEach(link => link.classList.remove("active"));
      document.querySelector(`a[href="${location.href}"]`).classList.add("active");
    }
  
    function isScrolledIntoView(el) {
      var rect = el.getBoundingClientRect();
      var elemTop = rect.top;
      var elemBottom = rect.bottom;
      // Only completely visible elements return true:
      var isVisible = elemTop < (window.innerHeight / 4) && elemBottom >= 0;
      return isVisible;
    }
  
    function setCurrent(e) {
      e.map(i => {
        let top = didThisIntersectionHappenAtTop(i);
        // Page just loaded ... probably and a heading is in view
        if (i.time < 1000 && i.isIntersecting) {
          links.forEach(link => link.classList.remove("active"));
          links.filter(link => i.target.id === link.getAttribute("href").split("#")[1]).map(link => link.classList.add("active"));
        } else if (i.time < 1000) {
          // In this case page just loaded and no heading in view
          return;
        } else if (!top && i.isIntersecting === false) {
          // This section deals with scrolling up the page. First we find if the heading being scrolled off the bottom is the first H tag in source order.
          let indexOfThisHeading = getPriorHeading(i);
          if (indexOfThisHeading === 0) {
            // The first H tag just scrolled off the bottom of the viewport and it is the first H tag in source order
            links.forEach(link => link.classList.remove("active"));
          } else {
            // An H tag scrolled off the bottom. It isn't the first so make the previous heading active
            links.forEach(link => link.classList.remove("active"));
            links.filter(link => sections[indexOfThisHeading - 1].id === link.getAttribute("href").split("#")[1]).map(link => link.classList.add("active"));
          }
        } else if (i.isIntersecting) {
          // For all other instances we want to make this one active and the others not active
          links.forEach(link => link.classList.remove("active"));
          links.filter(link => i.target.id === link.getAttribute("href").split("#")[1]).map(link => link.classList.add("active"));
        }
      })
    }
  
    sections.forEach(h => { observeHtags.observe(h) });
  
    // if we click a toc link, highlight that regardless of its scroll position
    links.forEach(link => {
      link.addEventListener("click", e => {
        setTimeout(function() {
          hash = location.href;
            links.forEach(link_ => link_.classList.remove("active"));
            document.querySelector(`a[href="${hash}"]`).classList.add("active");
        }, 50);
        setTimeout(function() {
          hash = location.href;
          links.forEach(link_ => link_.classList.remove("active"));
          document.querySelector(`a[href="${hash}"]`).classList.add("active");
        }, 500);
      })
    });
  };
  
