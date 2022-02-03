#lang rosette

(define (check-ss-mitigation)
  (define-symbolic orig (bitvector 32))
  (define-symbolic goal (bitvector 32))
  
  (define top-half (extract 31 16 orig))
  (define bottom-half-src (extract 15 0 goal))

  (define tmp (concat top-half bottom-half-src))
  (define inverted (bvnot tmp))
  (verify (assert (&& (! (equal? orig inverted))
                      (! (equal? inverted goal))))))

  