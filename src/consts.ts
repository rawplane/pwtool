import type { Site, Page, Links, Socials } from "@types"

// Global
export const SITE: Site = {
  TITLE: "Rasya Adrian",
  DESCRIPTION: "Selamat datang di portfolio saya.",
  AUTHOR: "Rasya Adrian",
}

// Work Page
export const WORK: Page = {
  TITLE: "Pengalaman Kerja",
  DESCRIPTION: "Ini adalah halaman pengalaman kerja saya.",
}

// Blog Page
export const BLOG: Page = {
  TITLE: "Blog",
  DESCRIPTION: "Saya terkadang suka menulis blog.",
}

// Projects Page 
export const PROJECTS: Page = {
  TITLE: "Projects",
  DESCRIPTION: "Ini adalah halaman proyek projek saya.",
}

// Search Page
export const SEARCH: Page = {
  TITLE: "Search",
  DESCRIPTION: "Search all posts and projects by keyword.",
}

// Links
export const LINKS: Links = [
  { 
    TEXT: "Home", 
    HREF: "/", 
  },
  { 
    TEXT: "Pekerjaan", 
    HREF: "/work", 
  },
  { 
    TEXT: "Blog", 
    HREF: "/blog", // change this url to my blog cosmicraw
  },
  { 
    TEXT: "Projects", 
    HREF: "/projects", 
  },
]

// Socials
export const SOCIALS: Socials = [
  { 
    NAME: "Email",
    ICON: "email", 
    TEXT: "rasyaadrian1234@gmail.com",
    HREF: "rasyaadrian1234@gmail.com",
  },
  { 
    NAME: "Github",
    ICON: "github",
    TEXT: "cosmicraw",
    HREF: "https://github.com/cosmicraw"
  },
  { 
    NAME: "LinkedIn",
    ICON: "linkedin",
    TEXT: "Rasya Adrian",
    HREF: "https://www.linkedin.com/in/rasya-adrian-104a68275/",
  },
  
]

