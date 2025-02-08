// Authentication functions
class CTFAuth {
    static async register(email, password, username) {
        try {
            // Create user in Firebase Auth
            const userCredential = await firebase.auth().createUserWithEmailAndPassword(email, password);
            const user = userCredential.user;

            // Create user profile in Firestore
            await firebase.firestore().collection('users').doc(user.uid).set({
                username: username,
                email: email,
                points: 0,
                completedChallenges: [],
                createdAt: firebase.firestore.FieldValue.serverTimestamp()
            });

            return { success: true, user: user };
        } catch (error) {
            console.error('Registration error:', error);
            return { success: false, error: error.message };
        }
    }

    static async login(email, password) {
        try {
            const userCredential = await firebase.auth().signInWithEmailAndPassword(email, password);
            const user = userCredential.user;
            const userDoc = await firebase.firestore().collection('users').doc(user.uid).get();
            
            return { success: true, user: { ...userDoc.data(), uid: user.uid } };
        } catch (error) {
            console.error('Login error:', error);
            return { success: false, error: error.message };
        }
    }

    static async logout() {
        try {
            await firebase.auth().signOut();
            return { success: true };
        } catch (error) {
            console.error('Logout error:', error);
            return { success: false, error: error.message };
        }
    }

    static async getCurrentUser() {
        const user = firebase.auth().currentUser;
        if (!user) return null;

        const userDoc = await firebase.firestore().collection('users').doc(user.uid).get();
        return { ...userDoc.data(), uid: user.uid };
    }
}
