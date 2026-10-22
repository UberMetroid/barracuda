;; GNU Guix reproducible package & manifest definition for barracuda
;; Build Docker image:
;;   guix pack -f docker -S /bin=bin -S /etc=etc -S /share=share -m manifest.scm

(use-modules (guix packages)
             (guix gexp)
             (guix build-system gnu)
             (guix build-system trivial)
             ((guix licenses) #:prefix license:)
             (gnu packages bittorrent)
             (gnu packages vpn)
             (gnu packages linux)
             (gnu packages curl)
             (gnu packages certs)
             (gnu packages base)
             (gnu packages bash)
             (gnu packages video)
             (gnu packages rust)
             (gnu packages commencement))

;; 1. Source-built package definition (compiles all 5 crates from source inside Guix sandbox)
(define-public barracuda-from-source
  (package
    (name "barracuda-from-source")
    (version "0.1.0")
    (source (local-file "." "barracuda-checkout"
                        #:recursive? #t
                        #:select? (lambda (file stat)
                                    (not (or (string-contains file "/target")
                                             (string-contains file "/prebuilt")
                                             (string-contains file "/.git"))))))
    (build-system gnu-build-system)
    (native-inputs
     (list rust
           (list rust "cargo")
           gcc-toolchain))
    (arguments
     (list
      #:tests? #f
      #:phases
      #~(modify-phases %standard-phases
          (delete 'configure)
          (replace 'build
            (lambda _
              (setenv "HOME" "/tmp")
              (invoke "cargo" "build" "--release" "--offline")))
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let* ((out (assoc-ref outputs "out"))
                     (bin (string-append out "/bin"))
                     (etc (string-append out "/etc"))
                     (ssl (string-append etc "/ssl/certs")))
                (mkdir-p bin)
                (mkdir-p ssl)
                (for-each
                 (lambda (prog)
                   (install-file (string-append "target/release/" prog) bin))
                 '("barracuda-init"
                   "barracuda-wg"
                   "barracuda-portforward"
                   "barracuda-scrubber"
                   "barracuda-proxy"))
                (install-file "assets/pia-ca.rsa.4096.crt" ssl)))))))
    (home-page "https://git.clownhouse.io/jeryd/barracuda")
    (synopsis "Zero-dependency Rust VPN supervisor, PIA WireGuard manager, and media malware scrubber")
    (description
     "Barracuda is a hardened BitTorrent + VPN appliance for the *arr stack built with GNU Guix and 5 zero-dependency Rust binaries.")
    (license license:expat)))

;; 2. Fast packaging of the 5 statically-linked Rust binaries + /etc configuration
(define-public barracuda-suite
  (package
    (name "barracuda-suite")
    (version "0.1.0")
    (source (local-file "." "barracuda-static"
                        #:recursive? #t
                        #:select? (lambda (file stat)
                                    (or (string=? file ".")
                                        (string-contains file "/prebuilt")
                                        (string-contains file "/assets")))))
    (build-system trivial-build-system)
    (native-inputs (list coreutils))
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((src #$source)
                 (out #$output)
                 (bin (string-append out "/bin"))
                 (etc (string-append out "/etc"))
                 (ssl (string-append etc "/ssl/certs")))
            (mkdir-p bin)
            (mkdir-p ssl)
            (for-each
             (lambda (prog)
               (let ((src-bin (string-append src "/prebuilt/" prog))
                     (dst-bin (string-append bin "/" prog)))
                 (copy-file src-bin dst-bin)
                 (chmod dst-bin #o755)))
             '("barracuda-init"
               "barracuda-wg"
               "barracuda-portforward"
               "barracuda-scrubber"
               "barracuda-proxy"))
            (copy-file (string-append src "/assets/pia-ca.rsa.4096.crt")
                       (string-append ssl "/pia-ca.rsa.4096.crt"))
            (call-with-output-file (string-append etc "/passwd")
              (lambda (port)
                (display "root:x:0:0:root:/root:/bin/sh\nnobody:x:99:100:Unraid Nobody:/config:/bin/sh\n" port)))
            (call-with-output-file (string-append etc "/group")
              (lambda (port)
                (display "root:x:0:\nusers:x:100:nobody\n" port)))
            (call-with-output-file (string-append etc "/nsswitch.conf")
              (lambda (port)
                (display "hosts: files dns\n" port)))))))
    (home-page "https://git.clownhouse.io/jeryd/barracuda")
    (synopsis "Zero-dependency static Rust VPN supervisor, PIA WireGuard manager, and media malware scrubber")
    (description
     "Barracuda is a hardened BitTorrent + VPN appliance built with GNU Guix and 5 zero-dependency static Rust binaries (barracuda-init, barracuda-wg, barracuda-portforward, barracuda-scrubber, barracuda-proxy).")
    (license license:expat)))

(concatenate-manifests
 (list (packages->manifest (list barracuda-suite))
       (specifications->manifest
        '("qbittorrent-no-x"
          "wireguard-tools"
          "iproute2"
          "iptables"
          "curl"
          "nss-certs"
          "coreutils"
          "bash-minimal"
          "ffmpeg"))))
