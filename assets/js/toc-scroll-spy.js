// minimal TOC scroll spy using IntersectionObserver
(function() {
  'use strict';

  function init() {
    const toc = document.getElementById('TableOfContents');
    if (!toc) return;

    // find the scrollable sidebar container (.td-sidebar-toc)
    const scrollableSidebar = toc.closest('.td-sidebar-toc');
    if (!scrollableSidebar) return;

    const links = toc.querySelectorAll('a');
    const headings = Array.from(links).map(link => {
      const id = link.getAttribute('href').slice(1);
      return document.getElementById(id);
    }).filter(Boolean);

    if (headings.length === 0) return;

    let currentActiveId = headings[0].id; // start with first section active
    let isScrollingFromClick = false;
    let isAutoScrolling = false;
    let autoScrollTimeout = null;
    let isManuallyScrolling = false;
    let manualScrollTimeout = null;

    // function to check if element is at least partially visible in its scrollable container
    function isElementVisible(element, container) {
      const elementRect = element.getBoundingClientRect();
      const containerRect = container.getBoundingClientRect();

      // element is visible if any part of it overlaps with the container
      // only scroll when completely outside the viewport
      return (
        elementRect.bottom > containerRect.top &&
        elementRect.top < containerRect.bottom
      );
    }

    // function to check if user has scrolled near the bottom of the document
    function isNearDocumentBottom() {
      const scrollPosition = window.scrollY + window.innerHeight;
      const documentHeight = document.documentElement.scrollHeight;
      return scrollPosition >= documentHeight - 100; // within 100px of bottom
    }

    // function to update active link and gliding marker position
    function setActiveLink(id) {
      currentActiveId = id;
      let activeLink = null;
      let activeLinkIndex = -1;

      // first pass: find the active link and its index
      links.forEach((link, index) => {
        const href = link.getAttribute('href').slice(1);
        if (href === currentActiveId) {
          link.classList.add('active');
          activeLink = link;
          activeLinkIndex = index;
        } else {
          link.classList.remove('active');
        }
      });

      // second pass: apply "read" state to all links before the active one
      // if we're at the bottom of the document, also mark all remaining sections as read
      const atBottom = isNearDocumentBottom();

      links.forEach((link, index) => {
        if (index < activeLinkIndex) {
          link.classList.add('sidebar-toc-read');
        } else if (atBottom && index > activeLinkIndex) {
          // at document bottom: mark sections after active as read too
          link.classList.add('sidebar-toc-read');
        } else {
          link.classList.remove('sidebar-toc-read');
        }
      });

      // update gliding marker position
      if (activeLink) {
        const linkRect = activeLink.getBoundingClientRect();
        const tocRect = toc.getBoundingClientRect();

        // calculate marker position relative to TOC container
        // center the marker vertically on the link
        const markerTop = linkRect.top - tocRect.top + (linkRect.height / 2) - 9;

        // update CSS custom properties to move the marker
        toc.style.setProperty('--toc-marker-top', `${markerTop}px`);
        toc.style.setProperty('--toc-marker-opacity', '1');

        // scroll the active link into view if needed and not manually scrolling or already auto-scrolling
        if (!isManuallyScrolling && !isAutoScrolling && !isElementVisible(activeLink, scrollableSidebar)) {
          isAutoScrolling = true;

          // clear any pending auto-scroll timeout
          if (autoScrollTimeout) {
            clearTimeout(autoScrollTimeout);
          }

          // calculate the position to center the active link in the sidebar viewport
          // get the link's current position relative to the scrollable container
          const linkRect = activeLink.getBoundingClientRect();
          const containerRect = scrollableSidebar.getBoundingClientRect();
          const currentScroll = scrollableSidebar.scrollTop;

          // calculate where the link is relative to the container's scroll position
          const linkRelativeTop = linkRect.top - containerRect.top + currentScroll;
          const containerHeight = scrollableSidebar.clientHeight;
          const linkHeight = linkRect.height;

          // scroll to position the link in the center of the container (paging effect)
          const targetScrollTop = linkRelativeTop - (containerHeight / 2) + (linkHeight / 2);

          console.log('Paging scroll:', {
            linkRelativeTop,
            containerHeight,
            currentScroll,
            targetScrollTop,
            visible: isElementVisible(activeLink, scrollableSidebar)
          });

          scrollableSidebar.scrollTo({
            top: targetScrollTop,
            behavior: 'smooth'
          });

          // reset auto-scroll flag after animation completes
          autoScrollTimeout = setTimeout(() => {
            isAutoScrolling = false;
            autoScrollTimeout = null;
          }, 500);
        }
      }
    }

    // handle manual scrolling of TOC sidebar
    scrollableSidebar.addEventListener('scroll', () => {
      // don't treat click-initiated or auto-scrolls as manual
      if (isScrollingFromClick || isAutoScrolling) return;

      isManuallyScrolling = true;

      // clear existing timeout
      if (manualScrollTimeout) {
        clearTimeout(manualScrollTimeout);
      }

      // resume auto-scroll after 3 seconds of no scrolling
      manualScrollTimeout = setTimeout(() => {
        isManuallyScrolling = false;
      }, 3000);
    });

    // handle TOC link clicks
    links.forEach(link => {
      link.addEventListener('click', (e) => {
        const targetId = link.getAttribute('href').slice(1);

        // temporarily disable manual scroll detection and cancel any auto-scroll
        isManuallyScrolling = false;
        if (manualScrollTimeout) {
          clearTimeout(manualScrollTimeout);
        }

        isAutoScrolling = false;
        if (autoScrollTimeout) {
          clearTimeout(autoScrollTimeout);
        }

        setActiveLink(targetId);
        isScrollingFromClick = true;

        // reset flag after scroll completes
        setTimeout(() => {
          isScrollingFromClick = false;
        }, 1000);
      });
    });

    const observer = new IntersectionObserver(entries => {
      // skip observer updates if we just clicked a link
      if (isScrollingFromClick) return;

      // find the heading that's closest to the top of the viewport
      let closestHeading = null;
      let closestDistance = Infinity;

      headings.forEach(heading => {
        const rect = heading.getBoundingClientRect();
        const distance = Math.abs(rect.top);

        // if heading is above viewport or just entered, consider it
        if (rect.top <= window.innerHeight * 0.3 && distance < closestDistance) {
          closestDistance = distance;
          closestHeading = heading;
        }
      });

      // update active ID if we found a closest heading and it's different from current
      if (closestHeading && closestHeading.id !== currentActiveId) {
        setActiveLink(closestHeading.id);
      }
    }, {
      threshold: [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    });

    headings.forEach(heading => observer.observe(heading));

    // set initial active state
    setActiveLink(currentActiveId);
  }

  // wait for DOM to be ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
