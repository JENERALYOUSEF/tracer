// Challenge management functions
class CTFChallenges {
    static async submitFlag(challengeId, flag) {
        try {
            const user = firebase.auth().currentUser;
            if (!user) throw new Error('User not authenticated');

            // Get challenge details
            const challengeDoc = await firebase.firestore()
                .collection('challenges')
                .doc(challengeId)
                .get();

            if (!challengeDoc.exists) {
                throw new Error('Challenge not found');
            }

            const challenge = challengeDoc.data();

            // Check if user has already completed this challenge
            const userDoc = await firebase.firestore()
                .collection('users')
                .doc(user.uid)
                .get();

            const userData = userDoc.data();
            if (userData.completedChallenges.includes(challengeId)) {
                return { success: false, error: 'Challenge already completed' };
            }

            // Verify flag
            if (flag === challenge.flag) {
                // Update user's points and completed challenges
                await firebase.firestore().collection('users').doc(user.uid).update({
                    points: firebase.firestore.FieldValue.increment(challenge.points),
                    completedChallenges: firebase.firestore.FieldValue.arrayUnion(challengeId),
                    lastCompletedAt: firebase.firestore.FieldValue.serverTimestamp()
                });

                // Add to activity log
                await firebase.firestore().collection('activity').add({
                    userId: user.uid,
                    challengeId: challengeId,
                    points: challenge.points,
                    timestamp: firebase.firestore.FieldValue.serverTimestamp()
                });

                return { 
                    success: true, 
                    points: challenge.points,
                    message: 'Congratulations! Flag is correct!' 
                };
            }

            return { success: false, error: 'Incorrect flag' };
        } catch (error) {
            console.error('Submit flag error:', error);
            return { success: false, error: error.message };
        }
    }

    static async getLeaderboard() {
        try {
            const snapshot = await firebase.firestore()
                .collection('users')
                .orderBy('points', 'desc')
                .limit(10)
                .get();

            return snapshot.docs.map(doc => ({
                username: doc.data().username,
                points: doc.data().points
            }));
        } catch (error) {
            console.error('Leaderboard error:', error);
            return [];
        }
    }

    static async getUserProgress() {
        try {
            const user = firebase.auth().currentUser;
            if (!user) throw new Error('User not authenticated');

            const userDoc = await firebase.firestore()
                .collection('users')
                .doc(user.uid)
                .get();

            return userDoc.data();
        } catch (error) {
            console.error('Get progress error:', error);
            return null;
        }
    }

    static async getChallengeDetails(challengeId) {
        try {
            const doc = await firebase.firestore()
                .collection('challenges')
                .doc(challengeId)
                .get();

            if (!doc.exists) {
                throw new Error('Challenge not found');
            }

            const challenge = doc.data();
            // Don't send the flag to the client
            delete challenge.flag;
            
            return challenge;
        } catch (error) {
            console.error('Get challenge error:', error);
            return null;
        }
    }
}
