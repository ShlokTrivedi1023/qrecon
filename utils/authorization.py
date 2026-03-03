
class AuthorizationGate:
    def __init__(self, target):
        self.target = target
    def verify(self):
        print()
        print("=" * 60)
        print("  AUTHORIZATION VERIFICATION - MANDATORY")
        print("=" * 60)
        print()
        print("  Target: " + self.target)
        print()
        print("  [1] Written authorization from target owner")
        print("  [2] Target is within agreed testing scope")
        print("  [3] You accept full legal responsibility")
        print()
        qs = [
            "Written authorization confirmed? (yes/no): ",
            "Target within authorized scope?    (yes/no): ",
            "Accept full legal responsibility?  (yes/no): ",
        ]
        responses = [input("  " + q).strip().lower() for q in qs]
        if all(r == "yes" for r in responses):
            print()
            print("  [OK] Authorization confirmed.")
            print("=" * 60)
            return True
        return False
