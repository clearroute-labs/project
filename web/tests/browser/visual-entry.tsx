import { createRoot } from 'react-dom/client'
import '../../src/styles.css'
import { VisualFixture, readVisualFixtureState } from './visual-fixture'

const root = document.getElementById('root')
if (!root) throw new Error('Missing #root element for the visual fixture.')

createRoot(root).render(<VisualFixture state={readVisualFixtureState()} />)
