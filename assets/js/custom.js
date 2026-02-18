(() => {
  const TYPING_STRINGS = [
    "黒より黒く闇より暗き漆黒に我が深紅の混淆を望みたもう",
    "覚醒のとき来たれり",
    "無謬の境界に落ちし理",
    "無行の歪みとなりて現出せよ",
    "踊れ踊れ踊れ",
    "我が力の奔流に望むは崩壊なり",
    "並ぶ者なき崩壊なり",
    "万象等しく灰塵に帰し",
    "深淵より来たれ！",
    "これが人類最大の威力の攻撃手段",
    "これこそが究極の攻撃魔法",
    "explosion!"
  ];

  let typedInstance = null;

  const destroyTyped = () => {
    if (typedInstance) {
      typedInstance.destroy();
      typedInstance = null;
    }
  };

  const initTyped = async () => {
    const element = document.getElementById("typed");
    if (!element) return;

    // Wait for Typed.js library to load (max 5 seconds)
    let attempts = 0;
    while (!window.Typed && attempts < 100) {
      await new Promise(resolve => setTimeout(resolve, 50));
      attempts++;
    }

    if (!window.Typed) {
      // Fallback if Typed.js didn't load
      element.textContent = TYPING_STRINGS[0];
      return;
    }

    destroyTyped();
    element.innerHTML = "";

    typedInstance = new window.Typed("#typed", {
      strings: TYPING_STRINGS,
      typeSpeed: 50,
      fadeOut: true,
      fadeOutDelay: 0,
      cursorChar: "_",
      autoInsertCss: true,
      onComplete: (self) => {
        if (self?.cursor) {
          self.cursor.style.display = "none";
        }
      }
    });
  };

  const handleTypedElement = () => {
    const element = document.getElementById("typed");
    if (element && !element.textContent.trim()) {
      initTyped();
    }
  };

  // Initialize when DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", handleTypedElement);
  } else {
    handleTypedElement();
  }

  // Watch for DOM changes (page navigation)
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === "childList") {
        // Check if the mutation contains or is the #typed element
        const hasTyped = Array.from(mutation.addedNodes).some(node => {
          if (node.id === "typed") return true;
          if (node.nodeType === 1 && node.querySelector?.("#typed")) return true;
          return false;
        });

        if (hasTyped) {
          // Small delay to ensure element is fully rendered
          setTimeout(handleTypedElement, 10);
        }
      }
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
})();
