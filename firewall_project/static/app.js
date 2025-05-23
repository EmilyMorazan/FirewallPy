// window.onload = function () {
//   document.getElementById("mode-slider").value = 1; // Start in light mode
//   toggleMode({ value: 1 });
// };

function navigateTo(page) {
  fetch(page)
    .then((response) => response.text())
    .then((data) => {
      document.getElementById("content").innerHTML = data;
      //added:
      setupDarkModeListener(); // Call the function to set up the dark mode listener
    })
    .catch((error) => console.error("Error loading page:", error));
}
// additional changes:
function setupDarkModeListener() {
  const modeSlider = document.getElementById("mode-slider");

  if (modeSlider) {
    modeSlider.addEventListener("change", function () {
      toggleMode(this);
    });

    // Load saved theme on page load
    const savedTheme = localStorage.getItem("theme");
    console.log("Saved theme in js:", savedTheme); // Debugging line
    if (savedTheme === "dark") {
      modeSlider.value = 1;
      toggleMode(modeSlider);
    } else {
      modeSlider.value = 0;
      toggleMode(modeSlider);
    }
  }
}

document.addEventListener("DOMContentLoaded", function () {
  // Hide all tabs initially
  document.querySelectorAll(".tab-content").forEach((tab) => {
    tab.style.display = "none";
  });

  // Add event listeners to all tab buttons
  document.querySelectorAll(".tab-button").forEach((button) => {
    button.addEventListener("click", function () {
      let tabName = this.getAttribute("data-tab");
      showTab(tabName);
    });
  });
});

document.getElementById("monitor-btn").addEventListener("click", function () {
  window.location.href = "/monitor";
});

function showTab(tabName) {
  // Hide all tabs
  document.querySelectorAll(".tab-content").forEach((tab) => {
    tab.style.display = "none";
  });

  // Show the selected t  ab
  let selectedTab = document.getElementById(tabName);
  if (selectedTab) {
    selectedTab.style.display = "block";
  }
}

function loadPage(page) {
  fetch(`/${page}`)
    .then((response) => response.text()) // Fix typo
    .then((data) => {
      document.getElementById("content").innerHTML = data;
      console.log(
        "HTML Classes:",
        document.getElementById("content").classList
      ); // Debugging line
      //aditional changes:
      setupDarkModeListener(); // Call the function to set up the dark mode listener
    })
    .catch((error) => console.error("Error loading page:", error));
}

setInterval(loadData, 3000); // Refresh every 3 seconds

function showInfo() {
  const box = document.getElementById("infoBox");
  box.style.display = "block";

  setTimeout(() => {
    box.style.display = "none";
  }, 3000); // 3000 ms = 3 seconds

  const arrow = document.querySelector(".arrow");
  arrow.style.display = "block";

  setTimeout(() => {
    arrow.style.display = "none";
  }, 6000); // 6 seconds
}
// from info:

function toggleDarkMode() {
  document.body.classList.toggle("dark-mode");
}

document.addEventListener("DOMContentLoaded", function () {
  const modeSlider = parent.document.getElementById("mode-slider"); // <- read the mode from the first page

  if (modeSlider) {
    if (modeSlider.value == 1) {
      document.body.classList.add("dark-mode");
    } else {
      document.body.classList.remove("dark-mode");
    }

    // Listen for changes
    modeSlider.addEventListener("change", function () {
      if (this.value == 1) {
        document.body.classList.add("dark-mode");
      } else {
        document.body.classList.remove("dark-mode");
      }
    });
  }
});

function toggleMode(slider) {
  const body = document.body;
  const sidebar = document.querySelector(".sidebar");
  const video = document.getElementById("theme-video");
  const source = document.getElementById("theme-video-source");

  if (slider.value == 0) {
    // Light mode
    body.classList.remove("dark-mode");
    body.style.backgroundColor = "#033661";
    body.style.color = "black";
    sidebar.style.backgroundColor = "#7CB9E8";
    sidebar.style.color = "black";

    document.querySelectorAll(".card, .log-feed").forEach((element) => {
      element.style.backgroundColor = "#7CB9E8";
      element.style.color = "black";
    });

    // This one is for traffic:
    document.querySelectorAll(".traffic-card, .log-feed").forEach((element) => {
      element.style.backgroundColor = "#7CB9E8";
      element.style.color = "black";
    });

    // for network traffic:
    document.querySelectorAll(".network-card").forEach((element) => {
      element.style.backgroundColor = "#7CB9E8";
      element.style.color = "black";
    });

    // for ips card:
    document.querySelectorAll(".ips-card").forEach((element) => {
      element.style.backgroundColor = "#7CB9E8";
      element.style.color = "black";
    });

    // for log feed:
    document.querySelectorAll(".liveLog-card").forEach((element) => {
      element.style.backgroundColor = "#7CB9E8";
      element.style.color = "black";
    });

    // added for ligth mode:
    document.querySelectorAll(".sidebar svg").forEach((icon) => {
      icon.style.fill = "black";
    });

    document.querySelectorAll(".sidebar button").forEach((button) => {
      button.style.color = "black";
    });

    source.src = "/static/video1.mp4";

    // 👉 Save to localStorage
    localStorage.setItem("theme", "light");
    console.log("Light mode activated", localStorage.getItem("theme"));
  } else {
    // Dark mode
    body.classList.add("dark-mode");
    body.style.backgroundColor = "#121212";
    sidebar.style.backgroundColor = "black";
    body.style.color = "green";
    sidebar.style.color = "green";

    // added for dark mode:
    document.querySelectorAll(".sidebar svg").forEach((icon) => {
      icon.style.fill = "green";
    });

    document.querySelectorAll(".card, .log-feed").forEach((element) => {
      element.style.backgroundColor = "#1e1e1e";
      element.style.color = "green";
    });

    //for network traffic:
    document.querySelectorAll(".network-card").forEach((element) => {
      element.style.backgroundColor = "#1e1e1e";
      element.style.color = "green";
    });

    // for ips card:
    document.querySelectorAll(".ips-card").forEach((element) => {
      element.style.backgroundColor = "#1e1e1e";
      element.style.color = "green";
    });

    // for liveLog feed:
    document.querySelectorAll(".liveLog-card").forEach((element) => {
      element.style.backgroundColor = "#1e1e1e";
      element.style.color = "green";
    });

    // This one is for traffic(change the color of the background):
    document.querySelectorAll(".traffic-card, .log-feed").forEach((element) => {
      element.style.backgroundColor = "#1e1e1e";
      element.style.color = "green";
    });

    document.querySelectorAll(".sidebar button").forEach((button) => {
      button.style.color = "green";
    });

    const arrow = document.querySelector(".arrow");
    if (arrow) {
      arrow.style.display = "none";
    }

    source.src = "/static/video2.mp4";

    // 👉 Save to localStorage
    localStorage.setItem("theme", "dark");
    console.log("Dark mode activated", localStorage.getItem("theme"));
  }

  video.load();
  video.play();
}

// addtional chnages;

document.addEventListener("DOMContentLoaded", function () {
  // Setup dark mode once at startup
  setupDarkModeListener();

  // Hide all tabs initially
  document.querySelectorAll(".tab-content").forEach((tab) => {
    tab.style.display = "none";
  });

  // Add event listeners to all tab buttons
  document.querySelectorAll(".tab-button").forEach((button) => {
    button.addEventListener("click", function () {
      let tabName = this.getAttribute("data-tab");
      showTab(tabName);
    });
  });

  // Initial theme from localStorage (optional fallback)
  const savedTheme = localStorage.getItem("theme");
  if (savedTheme === "dark") {
    document.body.classList.add("dark-mode");
  } else {
    document.body.classList.remove("dark-mode");
  }
});

// added for dashboard: